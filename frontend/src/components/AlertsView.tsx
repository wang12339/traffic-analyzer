import React, { useState } from 'react';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';
import { getAlerts, getAnomalies, resolveDeviceAlerts, AnomalyEvent } from '../utils/api';

const RISK_COLORS = ['var(--success)', 'var(--warning)', 'var(--danger)'];
function riskColor(score: number): string {
  if (score >= 75) return RISK_COLORS[2];
  if (score >= 50) return RISK_COLORS[1];
  return RISK_COLORS[0];
}

function AnomalyCard({ event }: { event: AnomalyEvent }) {
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState(false);
  const color = riskColor(event.risk_score);

  const handleResolve = async (ip: string) => {
    setResolving(true);
    try {
      await resolveDeviceAlerts(ip);
      setResolved(true);
    } catch { /* ignore */ }
    setResolving(false);
  };

  if (resolved) return null;

  return (
    <div style={{
      background: 'var(--bg-card)', borderRadius: 10,
      border: `1px solid ${event.risk_score >= 75 ? '#3a2020' : '#2a2a3a'}`,
      borderLeft: `3px solid ${color}`,
      padding: '10px 14px', marginBottom: 8, fontSize: 13,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            background: color, color: '#fff', padding: '2px 8px',
            borderRadius: 4, fontSize: 12, fontWeight: 600,
          }}>
            {event.risk_score}
          </span>
          <b>{event.src_ip}</b>
          {event.src_mac && (
            <span style={{ fontSize: 11, color: 'var(--text-secondary)', background: 'var(--bg-hover)', padding: '1px 6px', borderRadius: 4 }}>
              {event.src_mac.slice(-8)}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {event.timestamp?.substring(5, 16) || ''}
          </span>
          <button
            onClick={() => handleResolve(event.src_ip)}
            disabled={resolving}
            style={{
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: 6, padding: '3px 10px', fontSize: 11,
              color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            {resolving ? '...' : '忽略'}
          </button>
        </div>
      </div>
      <div style={{ marginTop: 4, color: 'var(--text-secondary)' }}>
        {event.reason}
      </div>
      <div style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)', opacity: 0.7 }}>
        {event.details}
      </div>
    </div>
  );
}

export function AlertsView() {
  const anomalies = useApi(() => getAnomalies(), [], { interval: 15000 });
  const alerts = useApi(() => getAlerts(), [], { interval: 15000 });

  if (anomalies.loading && !anomalies.data) {
    return <LoadingSpinner message="加载告警数据..." />;
  }
  if (anomalies.error) {
    return <ErrorState error={anomalies.error} onRetry={anomalies.refetch} />;
  }

  const anomalyData = anomalies.data;
  const alertData = alerts.data;
  const anomalyEvents = anomalyData?.events || [];
  const trafficAlerts = alertData?.traffic_alerts || [];
  const summary = anomalyData?.summary;

  // Group anomaly events by IP for summary
  const uniqueIps = new Set(anomalyEvents.map((e: AnomalyEvent) => e.src_ip));
  const highRisk = anomalyEvents.filter((e: AnomalyEvent) => e.risk_score >= 75);

  return (
    <div>
      {/* KPI Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border)', padding: '12px 16px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>异常事件 (24h)</div>
          <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{summary?.total || 0}</div>
        </div>
        <div style={{ background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border)', padding: '12px 16px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>受影响设备</div>
          <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{summary?.affected_devices || 0}</div>
        </div>
        <div style={{ background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border)', padding: '12px 16px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>高风险事件</div>
          <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: 'var(--danger)' }}>{highRisk.length}</div>
        </div>
        <div style={{ background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border)', padding: '12px 16px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>平均风险分</div>
          <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>
            {summary?.avg_risk ? (summary.avg_risk as number).toFixed(0) : '0'}
          </div>
        </div>
      </div>

      {/* Behavioral Anomaly Events */}
      {anomalyEvents.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
            🧠 行为异常检测
            <span style={{ fontSize: 11, background: highRisk.length > 0 ? 'var(--danger)' : 'var(--warning)', color: '#fff', padding: '1px 8px', borderRadius: 8 }}>
              {anomalyEvents.length} 事件 · {uniqueIps.size} 设备
            </span>
          </h3>
          {anomalyEvents.map((event: AnomalyEvent, i: number) => (
            <AnomalyCard key={`${event.src_ip}-${event.timestamp}-${i}`} event={event} />
          ))}
        </div>
      )}

      {anomalyEvents.length === 0 && (
        <div style={{ marginBottom: 20 }}>
          <EmptyState message="暂无异常告警" icon="✅" />
        </div>
      )}

      {/* Traffic-based Alerts (legacy) */}
      {trafficAlerts.length > 0 && (
        <div>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
            📊 流量异常 (启发式)
          </h3>
          <div style={{ background: 'var(--bg-card)', borderRadius: 12, border: '1px solid var(--border)', overflow: 'hidden' }}>
            {trafficAlerts.map((r: any) => (
              <div key={r.src_ip} style={{
                padding: '10px 14px', borderBottom: '1px solid var(--border)',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 13,
              }}>
                <div>
                  <b>{r.src_ip}</b>
                  <span style={{ marginLeft: 10, color: 'var(--text-secondary)' }}>
                    {r.dests}目标 · {r.apps}应用
                  </span>
                </div>
                <span style={{ color: (r.bytes || 0) > 10000000 ? 'var(--danger)' : 'var(--warning)' }}>
                  {(r.bytes / 1024 / 1024).toFixed(1)}MB
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {anomalyEvents.length === 0 && trafficAlerts.length === 0 && (
        <EmptyState message="暂无任何告警" icon="✅" />
      )}
    </div>
  );
}
