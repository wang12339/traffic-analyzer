import React from 'react';
import { getTopology } from '../utils/api';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';

export function TopologyView() {
  const topo = useApi(() => getTopology(), [], { interval: 15000 });

  if (topo.loading && !topo.data) return <LoadingSpinner message="加载拓扑..." />;
  if (topo.error) return <ErrorState error={topo.error} onRetry={topo.refetch} />;
  if (!topo.data || topo.data.length === 0) return <EmptyState message="暂无拓扑数据" icon="🗺️" />;

  const data = topo.data;
  const devs = [...new Set(data.map((r:any) => r.src_ip))].slice(0,15);
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
