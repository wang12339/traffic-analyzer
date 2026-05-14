import React, { useEffect, useState } from 'react';
import { TYPE_ICONS, fmt } from './KpiBox';

export function DeviceDetail({ ip, onBack }: { ip: string; onBack: () => void }) {
  const [profile, setProfile] = useState<any>(null);
  const [current, setCurrent] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [appBreakdown, setAppBreakdown] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetch(`/api/insights`).then(r=>r.json()),
      fetch(`/api/device/${ip}/current`).then(r=>r.json()),
      fetch(`/api/device/${ip}/anomalies`).then(r=>r.json()),
      fetch(`/api/device/${ip}`).then(r=>r.json()),
    ]).then(([ins, cur, anm, det]) => {
      if (ins.success) {
        const dev = ins.data.devices?.find((d: any) => d.ip === ip);
        if (dev) setProfile(dev);
      }
      if (cur.success) setCurrent(cur.data);
      if (anm.success) setAnomalies(anm.data);
      if (det.success) {
        const appMap: Record<string, {bytes:number; flows:number}> = {};
        for (const r of det.data) {
          const key = r.app_name || r.sni || r.dns_domain || 'other';
          if (!appMap[key]) appMap[key] = {bytes:0, flows:0};
          appMap[key].bytes += r.total_bytes || 0;
          appMap[key].flows += r.flow_count || 0;
        }
        setAppBreakdown(Object.entries(appMap).map(([k,v]) => ({name:k, ...v})).sort((a,b)=>b.bytes-a.bytes));
        setHistory(det.data.slice(0, 30));
      }
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [ip]);

  if (loading) return <div style={{padding:60, textAlign:'center', color:'var(--text-secondary)'}}>加载设备数据...</div>;

  const icon = (profile && TYPE_ICONS[profile.type]) || '❓';

  return (
    <div>
      <div style={{display:'flex', alignItems:'center', gap:12, marginBottom:20}}>
        <button onClick={onBack} style={{background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:8, padding:'8px 14px', color:'var(--text-primary)', cursor:'pointer', fontSize:13}}>← 返回</button>
        <span style={{fontSize:28}}>{icon}</span>
        <div>
          <h2 style={{fontSize:18, fontWeight:600}}>{ip}</h2>
          <div style={{display:'flex', gap:8, fontSize:13, color:'var(--text-secondary)', marginTop:2}}>
            {profile && <span>{profile.type} · {profile.os}</span>}
            {profile?.mac && <span style={{background:'var(--bg-hover)', padding:'1px 6px', borderRadius:4, fontSize:11}}>{profile.mac}</span>}
            {profile?.confidence !== undefined && <span>置信度 {(profile.confidence*100).toFixed(0)}%</span>}
          </div>
        </div>
      </div>

      <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16, marginBottom:16}}>
        <h3 style={{fontSize:14, fontWeight:600, marginBottom:10}}>当前活动</h3>
        {current.length > 0 ? (
          <div>
            {current.slice(0, 10).map((r: any, i: number) => (
              <div key={i} style={{display:'flex', justifyContent:'space-between', padding:'6px 0', fontSize:13, borderBottom:'1px solid var(--border)', alignItems:'center'}}>
                <div style={{display:'flex', gap:8, alignItems:'center', overflow:'hidden', flex:1}}>
                  {r.app_name && <span style={{fontSize:11, background:'var(--accent)', color:'#fff', padding:'1px 6px', borderRadius:4, whiteSpace:'nowrap'}}>{r.app_name}</span>}
                  <span style={{overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{r.sni || r.dns_domain || '(直接连接)'}</span>
                </div>
                <span style={{color:'var(--text-secondary)', whiteSpace:'nowrap', marginLeft:12}}>{fmt(r.bytes || r.bytes_total || 0)} / {r.flows || r.flow_count || 0}次</span>
              </div>
            ))}
          </div>
        ) : <div style={{color:'var(--text-secondary)', fontSize:13, padding:10}}>当前无活跃连接</div>}
      </div>

      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:16}}>
        <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16}}>
          <h3 style={{fontSize:14, fontWeight:600, marginBottom:10}}>应用分布 (24h)</h3>
          {appBreakdown.slice(0, 8).map((a, i) => (
            <div key={i} style={{display:'flex', justifyContent:'space-between', padding:'5px 0', fontSize:13, borderBottom:'1px solid var(--border)'}}>
              <span style={{overflow:'hidden', textOverflow:'ellipsis', maxWidth:'70%'}}>{a.name}</span>
              <span style={{color:'var(--text-secondary)'}}>{fmt(a.bytes)}</span>
            </div>
          ))}
        </div>

        <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16}}>
          <h3 style={{fontSize:14, fontWeight:600, marginBottom:10}}>异常检测</h3>
          <div style={{marginBottom:10}}>
            <div style={{fontSize:12, color:'var(--text-secondary)', marginBottom:4}}>行为偏离度</div>
            <div style={{height:8, background:'var(--bg-hover)', borderRadius:4, overflow:'hidden'}}>
              {(profile?.risk_score || 0) > 0 && <div style={{height:'100%', width:`${Math.min(profile?.risk_score||0,100)}%`, background:'var(--danger)', borderRadius:4}} />}
            </div>
            <div style={{fontSize:13, fontWeight:600, marginTop:2, color: (profile?.risk_score||0) > 50 ? 'var(--danger)' : 'var(--text-secondary)'}}>
              风险评分 {profile?.risk_score || 0}/100
            </div>
          </div>
          {anomalies?.first_seen?.length > 0 ? (
            <div>
              <div style={{fontSize:12, color:'var(--text-secondary)', marginBottom:6}}>🆕 首次访问 ({anomalies.first_seen.length}个)</div>
              {anomalies.first_seen.slice(0, 10).map((d: string, i: number) => (
                <div key={i} style={{fontSize:12, padding:'3px 0', borderBottom:'1px solid var(--border)', color:'var(--warning)'}}>{d}</div>
              ))}
              {anomalies.first_seen.length > 10 && <div style={{fontSize:12, color:'var(--text-secondary)', marginTop:4}}>+{anomalies.first_seen.length-10} 更多</div>}
            </div>
          ) : (
            <div style={{color:'var(--text-secondary)', fontSize:13}}>未发现异常</div>
          )}
          <div style={{marginTop:8, fontSize:11, color:'var(--text-secondary)'}}>
            基线: {anomalies?.baseline_size || 0} 个已知目标
          </div>
        </div>
      </div>

      <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16}}>
        <h3 style={{fontSize:14, fontWeight:600, marginBottom:10}}>历史活动 (24h)</h3>
        <div style={{maxHeight:400, overflow:'auto'}}>
          {history.map((r: any, i: number) => (
            <div key={i} style={{display:'flex', justifyContent:'space-between', padding:'5px 0', fontSize:12, borderBottom:'1px solid var(--border)'}}>
              <div style={{display:'flex', gap:8, overflow:'hidden', flex:1}}>
                {r.app_name && <span style={{color:'var(--accent)', whiteSpace:'nowrap'}}>{r.app_name}</span>}
                <span style={{overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{r.sni || r.dns_domain || '(直接连接)'}</span>
              </div>
              <span style={{color:'var(--text-secondary)', whiteSpace:'nowrap', marginLeft:8}}>{fmt(r.total_bytes || 0)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
