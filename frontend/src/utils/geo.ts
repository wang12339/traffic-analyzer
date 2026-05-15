const CACHE_KEY = 'geoip_cache';
const CACHE_TTL = 86400000; // 24h

interface GeoCache {
  [ip: string]: { data: GeoLocation; ts: number };
}

export interface GeoLocation {
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lon: number;
}

function getCache(): GeoCache {
  try {
    return JSON.parse(localStorage.getItem(CACHE_KEY) || '{}');
  } catch {
    return {};
  }
}

function setCache(ip: string, loc: GeoLocation) {
  const cache = getCache();
  cache[ip] = { data: loc, ts: Date.now() };
  const cutoff = Date.now() - CACHE_TTL;
  for (const [k, v] of Object.entries(cache)) {
    if (v.ts < cutoff) delete cache[k];
  }
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
  } catch { /* quota exceeded */ }
}

async function lookupIPs(ips: string[]): Promise<Map<string, GeoLocation>> {
  const map = new Map<string, GeoLocation>();
  if (ips.length === 0) return map;

  try {
    const resp = await fetch(`/api/geo-lookup?ips=${ips.join(',')}`);
    if (!resp.ok) return map;
    const json = await resp.json();
    if (!json.success) return map;

    const data = json.data as Record<string, { country: string; countryCode: string; city: string; lat: number; lon: number }>;
    for (const [ip, loc] of Object.entries(data)) {
      map.set(ip, { country: loc.country, countryCode: loc.countryCode, city: loc.city, lat: loc.lat, lon: loc.lon });
      setCache(ip, loc);
    }
  } catch {
    // silently fail
  }
  return map;
}

export async function resolveIPs(ips: string[]): Promise<Map<string, GeoLocation>> {
  const cache = getCache();
  const result = new Map<string, GeoLocation>();
  const uncached: string[] = [];
  const now = Date.now();

  for (const ip of ips) {
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      continue;
    }
    const cached = cache[ip];
    if (cached && (now - cached.ts) < CACHE_TTL) {
      result.set(ip, cached.data);
    } else {
      uncached.push(ip);
    }
  }

  if (uncached.length === 0) return result;

  // Look up in batches of 50 to avoid URL length issues
  const batchSize = 50;
  for (let i = 0; i < uncached.length; i += batchSize) {
    const batch = uncached.slice(i, i + batchSize);
    const lookup = await lookupIPs(batch);
    for (const [ip, loc] of lookup) result.set(ip, loc);
  }

  return result;
}

export async function resolveFlowIPs(flows: any[]): Promise<Map<string, GeoLocation>> {
  const ips = new Set<string>();
  for (const f of flows) {
    if (f.dst_ip) ips.add(f.dst_ip);
    if (f.src_ip) ips.add(f.src_ip);
  }
  return resolveIPs([...ips]);
}
