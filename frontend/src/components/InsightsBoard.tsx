import React from 'react';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState } from './LoadingState';
import { KpiBox, TYPE_ICONS, fmt } from './KpiBox';

export function InsightsBoard({ onDeviceClick }: { onDeviceClick?: (ip: string) => void }) {
  const insights = useApi(
    () => fetch('/api/insights').then(r => r.json()).then(j => j.success ? j.data : Promise.reject(j.error)),
    [],
    { interval: 8000 }
  );

  if (insights.loading && !insights.data) return <LoadingSpinner message="加载洞见数据..." />;
  if (insights.error) return <ErrorState error={insights.error} onRetry={insights.refetch} />;
  if (!insights.data) return null;

  const data = insights.data;
  const s = data.summary;
  const riskCount = data.alerts.length;

  return (
    <div>
      <div style={{display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:12, marginBottom:20}}>
        <KpiBox label="活跃设备" value={s.active_devices} />
        <KpiBox label="高风险" value={s.high_risk_devices} color="var(--danger)" />
        <KpiBox label="告警数" value={s.total_alerts} color={riskCount > 0 ? 'var(--warning)' : ''} />
        <KpiBox label="iOS/Android/Win" value={`${s.os_breakdown['iOS/macOS'] || 0}/${s.os_breakdown['Android'] || 0}/${s.os_breakdown['Windows'] || 0}`} />
        <KpiBox label="实时状态" value={riskCount > 0 ? "有异常" : "正常"} color={riskCount > 0 ? 'var(--warning)' : 'var(--success)'} />
      </div>

      {data.alerts.length > 0 && (
        <div style={{marginBottom:20}}>
          <h3 style={{fontSize:14, fontWeight:600, marginBottom:10, display:'flex', alignItems:'center', gap:8}}>
            <span>🚨 实时告警</span>
            <span style={{fontSize:11, background:'var(--danger)', color:'#fff', padding:'1px 8px', borderRadius:8}}>{data.alerts.length}</span>
          </h3>
          {data.alerts.map((a: any) => (
            <div key={a.ip} style={{background:'var(--bg-card)', borderRadius:10, border:'1px solid #3a2020', borderLeft:'3px solid var(--danger)', padding:'10px 16px', marginBottom:8, fontSize:13}}>
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                <span><b>{a.ip}</b> {a.type && `— ${a.type} (${a.os})`}</span>
                <span style={{background:'var(--danger)', color:'#fff', padding:'2px 8px', borderRadius:4, fontSize:12}}>风险 {a.risk}%</span>
              </div>
              <div style={{marginTop:4, color:'var(--text-secondary)'}}>{a.reason}</div>
            </div>
          ))}
        </div>
      )}

      <h3 style={{fontSize:14, fontWeight:600, marginBottom:10}}>设备清单 · 按风险排序</h3>
      <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', overflow:'hidden'}}>
        {data.devices.map((d: any) => {
          const icon = TYPE_ICONS[d.type] || '❓';
          const risk = d.risk_score || 0;
          const barColor = risk > 50 ? 'var(--danger)' : risk > 20 ? 'var(--warning)' : 'var(--success)';
          return (
            <div key={d.ip} onClick={() => onDeviceClick?.(d.ip)} style={{padding:'10px 16px', borderBottom:'1px solid var(--border)', fontSize:13, cursor: onDeviceClick ? 'pointer' : undefined}}
            onMouseEnter={e => { if (onDeviceClick) e.currentTarget.style.background = 'var(--bg-hover)'; }}
            onMouseLeave={e => { if (onDeviceClick) e.currentTarget.style.background = ''; }}>
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                <div style={{display:'flex', alignItems:'center', gap:8}}>
                  <span style={{fontSize:18}}>{icon}</span>
                  <b>{d.ip}</b>
                  {d.type !== 'Unknown' && <span style={{fontSize:12, color:'var(--accent)'}}>{d.type} · {d.os}</span>}
                  {d.mac && <span style={{fontSize:11, color:'var(--text-secondary)', background:'var(--bg-hover)', padding:'1px 6px', borderRadius:4}}>{d.mac.slice(-8)}</span>}
                </div>
                <div style={{display:'flex', gap:12, alignItems:'center'}}>
                  <span style={{fontSize:12, color:'var(--text-secondary)'}}>{fmt(d.bytes_total)} / {d.flows_total}流</span>
                  <div style={{width:60, height:6, background:'var(--bg-hover)', borderRadius:3, overflow:'hidden'}}>
                    <div style={{width:`${Math.min(risk,100)}%`, height:'100%', background:barColor, borderRadius:3}} />
                  </div>
                  <span style={{fontSize:12, fontWeight:600, color:barColor, minWidth:30, textAlign:'right'}}>{risk}%</span>
                </div>
              </div>
              {d.apps && d.apps.length > 0 && (
                <div style={{marginTop:4, display:'flex', gap:4, flexWrap:'wrap'}}>
                  {d.apps.slice(0, 6).map((a: string) => (
                    <span key={a} style={{fontSize:11, background:'var(--accent)', color:'#fff', padding:'1px 8px', borderRadius:6}}>{a}</span>
                  ))}
                  {d.apps.length > 6 && <span style={{fontSize:11, color:'var(--text-secondary)'}}>+{d.apps.length-6}</span>}
                </div>
              )}
              {d.first_seen && d.first_seen.length > 0 && (
                <div style={{marginTop:3, fontSize:11, color:'var(--warning)', display:'flex', gap:4, flexWrap:'wrap'}}>
                  🆕 {d.first_seen.slice(0, 4).join(' · ')}
                  {d.first_seen.length > 4 && <span>+{d.first_seen.length-4}个新目标</span>}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
