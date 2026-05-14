import React, { useEffect, useState } from 'react';
import { getApps, getDns, getSni } from '../utils/api';
import type { AppRecord, DnsRecord, SniRecord } from '../utils/api';
import { fmt } from './KpiBox';

export function AppView({ since }: { since: string }) {
  const [apps, setApps] = useState<AppRecord[]>([]);
  const [dns, setDns] = useState<DnsRecord[]>([]);
  const [snis, setSnis] = useState<SniRecord[]>([]);
  useEffect(() => {
    Promise.all([getApps(since), getDns(since), getSni(since)])
      .then(([a,d,s]) => { setApps(a.filter(x=>x.app_name&&x.app_name!=='Unknown')); setDns(d); setSnis(s); })
      .catch(()=>{});
    const iv = setInterval(() => Promise.all([getApps(since), getDns(since), getSni(since)])
      .then(([a,d,s]) => { setApps(a.filter(x=>x.app_name&&x.app_name!=='Unknown')); setDns(d); setSnis(s); })
      .catch(()=>{}), 10000);
    return () => clearInterval(iv);
  }, [since]);
  const total = apps.reduce((s,a)=>s+a.total_bytes, 0);
  return (
    <div>
      {apps.length > 0 && <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:20, marginBottom:16}}>
        <h3 style={{marginBottom:14, fontSize:14, fontWeight:600}}>已识别应用</h3>
        {apps.map(a => {
          const pct = total > 0 ? (a.total_bytes/total*100).toFixed(1) : '0';
          return <div key={a.app_id} style={{marginBottom:10}}>
            <div style={{display:'flex', justifyContent:'space-between', fontSize:13, marginBottom:3}}>
              <span style={{fontWeight:500}}>{a.app_name}</span>
              <span style={{color:'var(--text-secondary)'}}>{fmt(a.total_bytes)} / {a.flow_count}次 / {a.device_count}设备</span>
            </div>
            <div style={{height:6, background:'var(--bg-hover)', borderRadius:3, overflow:'hidden'}}>
              <div style={{height:'100%', width:`${pct}%`, background:'var(--accent)', borderRadius:3, minWidth:pct>'0'?4:0}} />
            </div>
          </div>;
        })}
      </div>}
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:16}}>
        <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16}}>
          <h3 style={{marginBottom:12, fontSize:14, fontWeight:600}}>DNS Top</h3>
          {dns.slice(0, 15).map(d => (
            <div key={d.dns_domain} style={{display:'flex', justifyContent:'space-between', padding:'4px 0', fontSize:13, borderBottom:'1px solid var(--border)'}}>
              <span style={{overflow:'hidden', textOverflow:'ellipsis', maxWidth:'65%'}}>{d.dns_domain}</span>
              <span style={{color:'var(--text-secondary)'}}>{d.count}次</span>
            </div>
          ))}
        </div>
        <div style={{background:'var(--bg-card)', borderRadius:12, border:'1px solid var(--border)', padding:16}}>
          <h3 style={{marginBottom:12, fontSize:14, fontWeight:600}}>HTTPS SNI Top</h3>
          {snis.slice(0, 15).map(s => (
            <div key={s.sni} style={{display:'flex', justifyContent:'space-between', padding:'4px 0', fontSize:13, borderBottom:'1px solid var(--border)'}}>
              <span style={{overflow:'hidden', textOverflow:'ellipsis', maxWidth:'65%'}}>{s.sni}</span>
              <span style={{color:'var(--text-secondary)'}}>{s.count}次</span>
            </div>
          ))}
          {snis.length === 0 && <div style={{color:'var(--text-secondary)', fontSize:13, padding:20}}>暂无 HTTPS SNI 数据</div>}
        </div>
      </div>
    </div>
  );
}
