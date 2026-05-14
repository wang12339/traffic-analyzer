import React, { useEffect, useState } from 'react';
import { KpiBox } from './KpiBox';

export function OverviewFull() {
  const [stats, setStats] = useState<any>(null);
  const [apps, setApps] = useState<any[]>([]);
  useEffect(() => {
    Promise.all([
      fetch('/api/stats?since=24h').then(r=>r.json()),
      fetch('/api/apps?since=24h').then(r=>r.json()),
    ]).then(([s, a]) => {
      if (s.success) setStats(s.data);
      if (a.success) setApps(a.data.filter((x:any)=>x.app_name&&x.app_name!='Unknown').sort((x:any,y:any)=>y.flow_count-x.flow_count).slice(0,20));
    }).catch(()=>{});
  }, []);
  if (!stats) return <div style={{padding:60,textAlign:'center',color:'var(--text-secondary)'}}>加载全景数据...</div>;
  return <div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:10,marginBottom:16}}>
      <KpiBox label="总流数" value={stats.total_flows?.toLocaleString()} />
      <KpiBox label="流量" value={(stats.total_bytes/1024/1024/1024).toFixed(2)+' GB'} />
      <KpiBox label="设备" value={stats.unique_devices} />
      <KpiBox label="应用" value={stats.active_apps} />
      <KpiBox label="域名" value={stats.unique_snis} />
      <KpiBox label="速率" value={stats.flows_per_sec?.toFixed(1)+'/s'} />
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16}}>
      <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
        <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>📱 应用排行</h3>
        {apps.map((a:any) => {
          const pct = stats.total_flows>0?(a.flow_count/stats.total_flows*100):0;
          return <div key={a.app_id} style={{marginBottom:6}}>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:12,marginBottom:1}}>
              <span>{a.app_name}</span><span style={{color:'var(--text-secondary)'}}>{a.flow_count}次 ({pct.toFixed(1)}%)</span>
            </div>
            <div style={{height:4,background:'var(--bg-hover)',borderRadius:2}}><div style={{height:'100%',width:Math.min(pct*3,100)+'%',background:'var(--accent)',borderRadius:2}} /></div>
          </div>;
        })}
      </div>
      <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
        <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>📊 分类汇总</h3>
        {[
          ['🤖 AI',['AI']],['💬 社交',['Social','Messaging']],['🎵 娱乐',['Music','Video']],
          ['☁️ 云服务',['Cloud','CDN']],['🛒 购物',['Shopping']],['📰 新闻',['News']],
          ['💼 办公',['Productivity']],['💳 支付',['Payment']],['🖥️ 系统',['System']],
        ].map(([label, cats]:any) => {
          const n = cats.reduce((s:number,c:any)=>s+apps.filter((a:any)=>a.app_category===c).reduce((s2:number,a2:any)=>s2+a2.flow_count,0),0);
          return <div key={label} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',fontSize:12,borderBottom:'1px solid var(--border)'}}>
            <span>{label}</span><span style={{color:'var(--text-secondary)'}}>{n}次</span>
          </div>;
        })}
      </div>
    </div>
  </div>;
}

