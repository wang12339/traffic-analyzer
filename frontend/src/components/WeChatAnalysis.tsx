import React, { useEffect, useState } from 'react';
import { KpiBox } from './KpiBox';

export function WeChatAnalysis() {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const load = async () => {
      try { const r = await fetch('/api/analysis/wechat'); const j = await r.json(); if (j.success) setData(j.data); }
      catch(e: any) { setError(e.message); }
    }; load(); const iv = setInterval(load, 15000); return () => clearInterval(iv);
  }, []);
  if (error) return <div style={{color:'var(--danger)'}}>{error}</div>;
  if (!data) return <div style={{padding:60,textAlign:'center',color:'var(--text-secondary)'}}>加载微信数据...</div>;
  const s = data.summary;
  return (
    <div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:12,marginBottom:20}}>
        <KpiBox label="总连接数" value={s.total_connections} />
        <KpiBox label="总流量" value={(s.total_bytes/1024/1024).toFixed(1)+' MB'} />
        <KpiBox label="占比" value={s.percent_of_total+'%'} color="var(--success)" />
        <KpiBox label="设备数" value={s.devices} />
        <KpiBox label="服务器" value={s.servers} />
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16}}>
        <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
          <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>🔗 连接类型分布</h3>
          {data.connection_types.map((t:any) => {
            const names: any = {heartbeat:'💓 心跳',short:'⚡ 短消息',msg:'💬 消息',file:'📎 文件',media:'🎥 音视频'};
            const tot = data.connection_types.reduce((s:any,x:any)=>s+parseInt(x.c),0);
            const allB = data.connection_types.reduce((s:any,x:any)=>s+parseInt(x.total_bytes),0);
            const bar = parseInt(t.c)/tot*100;
            return <div key={t.conn_type} style={{marginBottom:8}}>
              <div style={{display:'flex',justifyContent:'space-between',fontSize:12,marginBottom:2}}>
                <span>{names[t.conn_type]||t.conn_type}</span>
                <span style={{color:'var(--text-secondary)'}}>{t.c}次 ({(parseInt(t.c)/tot*100).toFixed(0)}%) · 流量占{allB>0?(parseInt(t.total_bytes)/allB*100).toFixed(0):0}%</span>
              </div>
              <div style={{height:5,background:'var(--bg-hover)',borderRadius:3,overflow:'hidden'}}>
                <div style={{height:'100%',width:Math.max(bar,1)+'%',background:'var(--accent)',borderRadius:3}} />
              </div>
            </div>;
          })}
        </div>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
          <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>⏰ 时段分布</h3>
          {data.hourly.map((h:any) => {
            const mx = Math.max(...data.hourly.map((x:any)=>x.flows));
            return <div key={h.h} style={{display:'flex',alignItems:'center',gap:8,padding:'3px 0',fontSize:13}}>
              <span style={{minWidth:36,color:'var(--text-secondary)'}}>{h.h}:00</span>
              <div style={{flex:1,height:18,background:'var(--bg-hover)',borderRadius:3,overflow:'hidden',position:'relative'}}>
                <div style={{height:'100%',width:mx>0?(h.flows/mx*100)+'%':'0%',background:'var(--success)',borderRadius:3,opacity:0.7}} />
                <span style={{position:'absolute',left:6,top:1,fontSize:11,color:'var(--text-primary)'}}>{h.flows}次</span>
              </div>
            </div>;
          })}
        </div>
        <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
          <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>🌐 微信服务器</h3>
          {data.domains.map((d:any) => (
            <div key={d.dns_domain} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',fontSize:12,borderBottom:'1px solid var(--border)'}}>
              <span style={{overflow:'hidden',textOverflow:'ellipsis',maxWidth:'70%'}}>{d.dns_domain}</span>
              <span style={{color:'var(--text-secondary)'}}>{d.hits}次/{d.devices}设备</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
