import React from 'react';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';
import { KpiBox } from './KpiBox';
import { getStats, getApps } from '../utils/api';

export function OverviewFull() {
  const stats = useApi(() => getStats('24h'), [], { interval: 8000 });
  const apps = useApi(() => getApps('24h'), [], { interval: 8000 });

  if (stats.loading && !stats.data) return <LoadingSpinner message="加载全景数据..." />;
  if (stats.error) return <ErrorState error={stats.error} onRetry={stats.refetch} />;
  if (!stats.data) return <EmptyState message="暂无全景数据" icon="📊" />;

  const s = stats.data;
  const appList = (apps.data || [])
    .filter((x: any) => x.app_name && x.app_name !== 'Unknown')
    .sort((x: any, y: any) => y.flow_count - x.flow_count)
    .slice(0, 20);

  const totalProto = (s.tcp_flows || 0) + (s.udp_flows || 0);
  const tcpPct = totalProto > 0 ? ((s.tcp_flows || 0) / totalProto * 100) : 0;
  const udpPct = totalProto > 0 ? ((s.udp_flows || 0) / totalProto * 100) : 0;

  return <div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:8}}>
      <KpiBox label="总流数" value={s.total_flows?.toLocaleString()} />
      <KpiBox label="流量" value={(s.total_bytes/1024/1024/1024).toFixed(2)+' GB'} />
      <KpiBox label="设备" value={s.unique_devices} />
      <KpiBox label="吞吐" value={(s.throughput_mbps || 0).toFixed(2)+' Mbps'} color="var(--accent)" />
    </div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:16,fontSize:12}}>
      <KpiBox label="应用" value={s.active_apps} />
      <KpiBox label="域名" value={s.unique_snis} />
      <KpiBox label="速率" value={s.flows_per_sec?.toFixed(1)+'/s'} />
      <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:'10px 14px'}}>
        <div style={{fontSize:11,color:'var(--text-secondary)',marginBottom:4}}>协议分布</div>
        <div style={{display:'flex',gap:0,height:8,borderRadius:4,overflow:'hidden'}}>
          <div style={{flex:tcpPct,background:'var(--accent)'}} title={`TCP ${tcpPct.toFixed(0)}%`} />
          <div style={{flex:Math.max(udpPct,1),background:'var(--warning)'}} title={`UDP ${udpPct.toFixed(0)}%`} />
        </div>
        <div style={{display:'flex',justifyContent:'space-between',marginTop:4,fontSize:11,color:'var(--text-secondary)'}}>
          <span>TCP {s.tcp_flows?.toLocaleString()} ({(s.tcp_flows/totalProto*100).toFixed(0)}%)</span>
          <span>UDP {s.udp_flows?.toLocaleString()} ({(s.udp_flows/totalProto*100).toFixed(0)}%)</span>
        </div>
      </div>
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16}}>
      <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:16}}>
        <h3 style={{fontSize:14,fontWeight:600,marginBottom:10}}>📱 应用排行</h3>
        {appList.length === 0 ? <EmptyState message="暂无应用数据" /> : appList.map((a: any) => {
          const pct = s.total_flows>0?(a.flow_count/s.total_flows*100):0;
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
        ].map(([label, cats]: any) => {
          const n = cats.reduce((s:number,c:any)=>s+appList.filter((a:any)=>a.app_category===c).reduce((s2:number,a2:any)=>s2+a2.flow_count,0),0);
          return <div key={label} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',fontSize:12,borderBottom:'1px solid var(--border)'}}>
            <span>{label}</span><span style={{color:'var(--text-secondary)'}}>{n}次</span>
          </div>;
        })}
      </div>
    </div>
  </div>;
}
