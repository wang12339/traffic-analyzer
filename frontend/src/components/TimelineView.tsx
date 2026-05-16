import React, { useState } from 'react';
import { getTimeline } from '../utils/api';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';

interface HourlyApp { h: number; app_name: string; c: number; }
interface SiteVisit { h: number; sni: string; dns_domain: string; c: number; }

export function TimelineView() {
  const [expandedHour, setExpandedHour] = useState<number | null>(null);

  const timeline = useApi(() => getTimeline(), []);

  if (timeline.loading && !timeline.data) return <LoadingSpinner message="加载时间线..." />;
  if (timeline.error) return <ErrorState error={timeline.error} onRetry={timeline.refetch} />;
  if (!timeline.data) return <EmptyState message="暂无时间线数据" icon="⏱" />;

  const apps: HourlyApp[] = timeline.data.hourly_apps || [];
  const sites: SiteVisit[] = timeline.data.visited_sites || [];

  // Aggregate apps by hour
  const hourlyMap = new Map<number, { apps: { name: string; count: number }[]; total: number }>();
  for (const a of apps) {
    if (!hourlyMap.has(a.h)) hourlyMap.set(a.h, { apps: [], total: 0 });
    const h = hourlyMap.get(a.h)!;
    h.apps.push({ name: a.app_name, count: a.c });
    h.total += a.c;
  }

  // Sites by hour
  const sitesByHour = new Map<number, { domain: string; count: number }[]>();
  for (const s of sites) {
    const domain = s.sni || s.dns_domain || '';
    if (!domain) continue;
    if (!sitesByHour.has(s.h)) sitesByHour.set(s.h, []);
    const list = sitesByHour.get(s.h)!;
    const existing = list.find(x => x.domain === domain);
    if (existing) existing.count += s.c;
    else list.push({ domain, count: s.c });
  }

  const hours = Array.from(hourlyMap.entries()).sort(([a], [b]) => a - b);

  if (hours.length === 0) return <EmptyState message="暂无时间线数据" icon="⏱" />;

  return (
    <div>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
        过去 24 小时应用和网站访问时间线
      </p>
      {hours.map(([hour, data]) => {
        const maxCount = Math.max(...data.apps.map(a => a.count));
        const topApps = data.apps.sort((a, b) => b.count - a.count).slice(0, 3);
        const siteList = (sitesByHour.get(hour) || []).sort((a, b) => b.count - a.count).slice(0, 8);
        const isExpanded = expandedHour === hour;

        return (
          <div key={hour} style={{
            background: 'var(--bg-card)', borderRadius: 10,
            border: '1px solid var(--border)', marginBottom: 6, overflow: 'hidden',
            borderLeft: `3px solid ${hour >= 6 && hour < 12 ? '#22c55e' : hour >= 12 && hour < 18 ? '#6366f1' : hour >= 18 && hour < 22 ? '#f59e0b' : '#6366f1'}`
          }}>
            <div
              onClick={() => setExpandedHour(isExpanded ? null : hour)}
              style={{ padding: '8px 14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}
            >
              <div style={{ minWidth: 42, textAlign: 'center' }}>
                <div style={{ fontSize: 16, fontWeight: 700, lineHeight: 1.2 }}>{hour}</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>:00</div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {topApps.map((app, i) => (
                    <span key={i} style={{
                      fontSize: 11, background: 'var(--bg-hover)',
                      padding: '2px 8px', borderRadius: 4,
                      display: 'flex', alignItems: 'center', gap: 4
                    }}>
                      <span style={{
                        display: 'inline-block', width: 6, height: 6, borderRadius: '50%',
                        background: i === 0 ? 'var(--accent)' : i === 1 ? '#22c55e' : '#f59e0b'
                      }} />
                      {app.name}
                      <span style={{ color: 'var(--text-secondary)' }}>{app.count}</span>
                    </span>
                  ))}
                  {data.apps.length > 3 && (
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)', padding: '2px 4px' }}>
                      +{data.apps.length - 3}
                    </span>
                  )}
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                {data.total} 次
              </div>
            </div>

            {isExpanded && siteList.length > 0 && (
              <div style={{ padding: '0 14px 8px 68px', borderTop: '1px solid var(--border)', paddingTop: 8 }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>访问的网站:</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {siteList.map((site, i) => (
                    <span key={i} style={{
                      fontSize: 11, background: 'var(--bg-hover)',
                      padding: '2px 8px', borderRadius: 4, color: 'var(--text-secondary)',
                      maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                    }}>
                      {site.domain}
                      <span style={{ color: 'var(--accent)', marginLeft: 4 }}>{site.count}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
