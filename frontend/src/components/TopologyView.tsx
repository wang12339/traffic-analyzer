import React, { useEffect, useState } from 'react';

export function TopologyView() {
  const [data, setData] = useState<any[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    const load = async () => {
      try { const r = await fetch('/api/topology'); const j = await r.json(); if (j.success) setData(j.data); }
      catch(e:any) { setError(e.message); }
    }; load(); const iv = setInterval(load, 15000); return () => clearInterval(iv);
  }, []);
  if (error) return <div>{error}</div>;
  if (!data.length) return <div style={{padding:40,textAlign:'center',color:'var(--text-secondary)'}}>暂无拓扑数据</div>;
  const devs = [...new Set(data.map((r:any)=>r.src_ip))].slice(0,15);
  return (
    <div>
      <div style={{fontSize:13,color:'var(--text-secondary)',marginBottom:12}}>过去1小时连接 ({data.length}条)</div>
      {devs.map((dev:any) => {
        const conns = data.filter((r:any)=>r.src_ip===dev).slice(0,10);
        return <div key={dev} style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',marginBottom:8,padding:'10px 14px',fontSize:13}}>
          <div style={{fontWeight:600,marginBottom:4}}>📡 {dev}</div>
          <div style={{display:'flex',flexWrap:'wrap',gap:4}}>
            {conns.map((c:any,i:number) => (
              <span key={i} style={{fontSize:11,background:'var(--bg-hover)',padding:'2px 8px',borderRadius:4}}>
                {c.dst_ip} {c.app_name && <span style={{color:'var(--accent)'}}>{c.app_name}</span>}
              </span>
            ))}
          </div>
        </div>;
      })}
    </div>
  );
}
