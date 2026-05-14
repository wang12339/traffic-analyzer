import React, { useEffect, useState } from 'react';
import { getStats } from './utils/api';
import type { Stats } from './utils/api';
import { InsightsBoard } from './components/InsightsBoard';
import { AppView } from './components/AppView';
import { DeviceDetail } from './components/DeviceDetail';
import { HttpView } from './components/HttpView';
import { AdminPanel } from './components/AdminPanel';
import { TopologyView } from './components/TopologyView';
import { AlertsView } from './components/AlertsView';
import { TimelineView } from "./components/TimelineView";
import { OverviewFull } from "./components/OverviewFull";
import { WeChatAnalysis } from './components/WeChatAnalysis';

export default function App() {
  const [tab, setTab] = useState('insights');
  const [since, setSince] = useState('30m');
  const [detailIp, setDetailIp] = useState<string|null>(null);
  const [stats, setStats] = useState<Stats|null>(null);
  useEffect(() => {
    getStats(since).then(setStats).catch(()=>{});
    const iv = setInterval(() => getStats(since).then(setStats).catch(()=>{}), 8000);
    return () => clearInterval(iv);
  }, [since]);
  const handleDeviceClick = (ip: string) => setDetailIp(ip);
  if (detailIp) {
    return (
      <div style={{maxWidth:1400, margin:'0 auto', padding:'20px 24px'}}>
        <DeviceDetail ip={detailIp} onBack={() => setDetailIp(null)} />
      </div>
    );
  }
  return (
    <div style={{maxWidth:1400, margin:'0 auto', padding:'20px 24px'}}>
      <header style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20}}>
        <div>
          <h1 style={{fontSize:22, fontWeight:700, letterSpacing:-0.3}}>流量分析系统</h1>
          <p style={{fontSize:13, color:'var(--text-secondary)', marginTop:2}}>
            {stats ? `${stats.total_flows}条流 · ${stats.unique_devices}台设备 · ${stats.flows_per_sec.toFixed(1)}流/秒` : '加载中...'}
          </p>
        </div>
        <select value={since} onChange={e=>setSince(e.target.value)} style={{background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:8, padding:'8px 12px', color:'var(--text-primary)', fontSize:13}}>
          <option value="15m">15分钟</option><option value="30m">30分钟</option><option value="1h">1小时</option>
        </select>
      </header>
      <div style={{display:'flex', gap:4, marginBottom:20, borderBottom:'1px solid var(--border)'}}>
        {[
          {k:'insights', l:'📊 洞察'},
          {k:'overview', l:'📈 全景'},
          {k:'timeline', l:'⏱ 时间线'},
          {k:'apps', l:'📱 应用'},
          {k:'wechat', l:'💬 微信'},
          {k:'http', l:'🔓 HTTP'},
          {k:'topo', l:'🗺️ 拓扑'},
          {k:'alerts', l:'🚨 告警'},
          {k:'admin', l:'⚙️ 管理'},
        ].map(t => (
          <button key={t.k} onClick={()=>setTab(t.k)}
            style={{padding:'10px 20px', fontSize:14, fontWeight:500, background:tab===t.k?'var(--accent)':'transparent', color:tab===t.k?'#fff':'var(--text-secondary)', border:'none', borderRadius:'8px 8px 0 0', cursor:'pointer'}}>{t.l}</button>
        ))}
      </div>
      {tab === 'overview' && <OverviewFull />}
      {tab === 'timeline' && <TimelineView />}
      {tab === 'insights' && <InsightsBoard onDeviceClick={handleDeviceClick} />}
      {tab === 'apps' && <AppView since={since} />}
      {tab === 'wechat' && <WeChatAnalysis />}
      {tab === 'http' && <HttpView />}
      {tab === 'topo' && <TopologyView />}
      {tab === 'alerts' && <AlertsView />}
      {tab === 'admin' && <AdminPanel />}
    </div>
  );
}
