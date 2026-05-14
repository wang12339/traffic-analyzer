import React from 'react';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';

export function AlertsView() {
  const alerts = useApi(
    () => fetch('/api/alerts').then(r => r.json()).then(j => j.success ? j.data : Promise.reject(j.error)),
    [],
    { interval: 10000 }
  );

  if (alerts.loading && !alerts.data) return <LoadingSpinner message="加载告警..." />;
  if (alerts.error) return <ErrorState error={alerts.error} onRetry={alerts.refetch} />;
  if (!alerts.data || alerts.data.length === 0) return <EmptyState message="暂无告警" icon="✅" />;

  return (
    <div>
      <div style={{marginBottom:12,fontSize:13,color:'var(--text-secondary)'}}>高活跃设备告警</div>
      {alerts.data.map((r:any) => (
        <div key={r.src_ip} style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',marginBottom:8,padding:'10px 14px',display:'flex',justifyContent:'space-between',alignItems:'center',fontSize:13}}>
          <div><b>{r.src_ip}</b> <span style={{marginLeft:10,color:'var(--text-secondary)'}}>{r.dests}目标 · {r.apps}应用</span></div>
          <span style={{color:(r.bytes||0)>10000000?'var(--danger)':'var(--warning)'}}>{(r.bytes/1024/1024).toFixed(1)}MB</span>
        </div>
      ))}
    </div>
  );
}
