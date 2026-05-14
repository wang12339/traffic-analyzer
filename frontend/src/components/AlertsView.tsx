import React, { useEffect, useState } from 'react';

export function AlertsView() {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    const load = async () => {
      try { const r = await fetch('/api/alerts'); const j = await r.json(); if (j.success) setData(j.data); }
      catch {}
    }; load(); const iv = setInterval(load, 10000); return () => clearInterval(iv);
  }, []);
  return (
    <div>
      <div style={{marginBottom:12,fontSize:13,color:'var(--text-secondary)'}}>高活跃设备告警</div>
      {data.map((r:any) => (
        <div key={r.src_ip} style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',marginBottom:8,padding:'10px 14px',display:'flex',justifyContent:'space-between',alignItems:'center',fontSize:13}}>
          <div><b>{r.src_ip}</b> <span style={{marginLeft:10,color:'var(--text-secondary)'}}>{r.dests}目标 · {r.apps}应用</span></div>
          <span style={{color:(r.bytes||0)>10000000?'var(--danger)':'var(--warning)'}}>{(r.bytes/1024/1024).toFixed(1)}MB</span>
        </div>
      ))}
      {!data.length && <div style={{padding:40,textAlign:'center',color:'var(--text-secondary)'}}>暂无告警</div>}
    </div>
  );
}
