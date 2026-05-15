const API_BASE = '/api';

export interface Stats {
  total_flows: number;
  total_bytes: number;
  active_apps: number;
  unique_devices: number;
  unique_snis: number;
  unique_domains: number;
  flows_per_sec: number;
  tcp_flows: number;
  udp_flows: number;
  throughput_mbps: number;
}

export interface FlowRecord {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  sni: string;
  ja3s: string;
  tls_version: string;
  server_cipher_suite: number;
  tls_signature_hash: string;
  dns_domain: string;
  app_name: string;
  app_category: string;
  confidence: number;
  bytes_up: number;
  bytes_down: number;
  packets_up: number;
  packets_down: number;
  duration_ms: number;
  src_mac: string;
  engines: string;
}

export interface DeviceRecord {
  src_ip: string;
  flows: number;
  bytes_total: number;
  app_count: number;
  last_seen: string;
  src_mac: string;
  app_names: string;
  sni_count: number;
}

export interface AppRecord {
  app_id: number;
  app_name: string;
  app_category: string;
  flow_count: number;
  total_bytes: number;
  device_count: number;
}

export interface DnsRecord {
  dns_domain: string;
  count: number;
  clients: number;
}

export interface SniRecord {
  sni: string;
  count: number;
  clients: number;
}

export interface TrendRecord {
  bucket: string;
  flows: number;
  bytes: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options?.headers },
    });
  } catch (err) {
    throw new ApiError(0, `Network error: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!resp.ok) {
    let body = '';
    try { body = await resp.text(); } catch { /* ignore */ }
    throw new ApiError(resp.status, `HTTP ${resp.status}: ${resp.statusText}${body ? ` - ${body.slice(0, 200)}` : ''}`);
  }

  let json: ApiResponse<T>;
  try {
    json = await resp.json();
  } catch (err) {
    throw new ApiError(resp.status, `Invalid JSON response: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!json.success) {
    throw new ApiError(resp.status, json.error || 'Unknown API error');
  }

  return json.data;
}

export function getStats(since = '24h'): Promise<Stats> {
  return fetchApi(`/stats?since=${since}`);
}

export function getFlows(params?: { limit?: number; search_ip?: string; search_domain?: string; since?: string }): Promise<FlowRecord[]> {
  const p = new URLSearchParams();
  if (params?.limit) p.set('limit', String(params.limit));
  if (params?.search_ip) p.set('search_ip', params.search_ip);
  if (params?.search_domain) p.set('search_domain', params.search_domain);
  if (params?.since) p.set('since', params.since);
  return fetchApi(`/flows?${p.toString()}`);
}

export function getApps(since = '24h'): Promise<AppRecord[]> {
  return fetchApi(`/apps?since=${since}`);
}

export function getDevices(since = '24h'): Promise<DeviceRecord[]> {
  return fetchApi(`/devices?since=${since}`);
}

export function getDns(since = '24h'): Promise<DnsRecord[]> {
  return fetchApi(`/dns?since=${since}`);
}

export function getSni(since = '24h'): Promise<SniRecord[]> {
  return fetchApi(`/sni?since=${since}`);
}

export function getTrends(since = '24h'): Promise<TrendRecord[]> {
  return fetchApi(`/trends?since=${since}`);
}

export function getDeviceDetail(ip: string): Promise<any[]> {
  return fetchApi(`/device/${encodeURIComponent(ip)}`);
}
