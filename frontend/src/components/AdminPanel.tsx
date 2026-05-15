import React, { useState, useEffect } from 'react';

export function AdminPanel() {
  const [status, setStatus] = useState<any>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [apiKey, setApiKey] = useState(sessionStorage.getItem('api_key') || '');

  useEffect(() => {
    if (!apiKey) return;
    const load = async () => {
      try {
        const r = await fetch('/api/admin/status', {headers:{'X-API-Key':apiKey}});
        const j = await r.json();
        if (j.success) setStatus(j.data);
      } catch { /* status fetch best-effort */ }
    };
    load(); const iv = setInterval(load, 5000); return () => clearInterval(iv);
  }, [apiKey]);

  if (!apiKey) return (
    <div style={{maxWidth:400,margin:'60px auto',background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:24}}>
      <h2 style={{fontSize:18,fontWeight:600,marginBottom:16}}>管理后台登录</h2>
      <input placeholder="输入 API Key" value={apiKey} onChange={e=>{setApiKey(e.target.value);sessionStorage.setItem('api_key',e.target.value)}}
        style={{width:'100%',padding:'10px 14px',background:'var(--bg-hover)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text-primary)',fontSize:14,marginBottom:12}} />
      <button onClick={() => {}} style={{width:'100%',padding:'10px',background:'var(--accent)',color:'#fff',border:'none',borderRadius:8,cursor:'pointer'}}>登录</button>
    </div>
  );

  return (
    <div>
      <h2 style={{fontSize:18,fontWeight:600,marginBottom:16}}>⚙️ 系统管理</h2>
      <nav style={{display:'flex',gap:4,marginBottom:16,borderBottom:'1px solid var(--border)'}}>
        {[
          {k:'overview',l:'📊 概览'},
          {k:'config',l:'🔧 配置'},
          {k:'logs',l:'📋 日志'},
        ].map(t => (
          <button key={t.k} onClick={()=>setActiveTab(t.k)}
            style={{padding:'8px 16px',fontSize:13,fontWeight:500,background:activeTab===t.k?'var(--accent)':'transparent',color:activeTab===t.k?'#fff':'var(--text-secondary)',border:'none',borderRadius:'8px 8px 0 0',cursor:'pointer'}}>{t.l}</button>
        ))}
      </nav>

      {activeTab==='overview' && status && <div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12,marginBottom:16}}>
          <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
            <div style={{fontSize:12,color:'var(--text-secondary)'}}>总流数</div>
            <div style={{fontSize:24,fontWeight:700}}>{status.flows?.toLocaleString()}</div>
          </div>
          <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
            <div style={{fontSize:12,color:'var(--text-secondary)'}}>解密请求</div>
            <div style={{fontSize:24,fontWeight:700}}>{status.http_sessions}</div>
          </div>
          <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
            <div style={{fontSize:12,color:'var(--text-secondary)'}}>最后一条流</div>
            <div style={{fontSize:13,fontWeight:600}}>{status.last_flow?.substring(0,19) || '-'}</div>
          </div>
        </div>
        <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
          <h3 style={{fontSize:13,fontWeight:600,marginBottom:8}}>系统信息</h3>
          <div style={{fontSize:12,color:'var(--text-secondary)',lineHeight:1.8}}>
            版本: {status.version}<br/>
            API 状态: <span style={{color:'var(--success)'}}>运行中</span><br/>
            ClickHouse: 已连接<br/>
            Ingest: TCP :9100 / UDP :2055<br/>
            MITM Proxy: :8081
          </div>
        </div>
      </div>}

      {activeTab==='config' && <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
        <h3 style={{fontSize:13,fontWeight:600,marginBottom:10}}>环境配置</h3>
        <div style={{fontSize:12,color:'var(--text-secondary)',lineHeight:2}}>
          API Key: <code style={{background:'var(--bg-hover)',padding:'2px 6px',borderRadius:4}}>{apiKey}</code><br/>
          数据保留: 90 天 (TTL)<br/>
          前端: http://localhost:3001<br/>
          API: http://localhost:8080<br/>
        </div>
      </div>}

      {activeTab==='logs' && <div style={{background:'var(--bg-card)',borderRadius:10,border:'1px solid var(--border)',padding:16}}>
        <h3 style={{fontSize:13,fontWeight:600,marginBottom:10}}>系统日志</h3>
        <p style={{fontSize:12,color:'var(--text-secondary)'}}>
          日志文件:<br/>
          <code style={{display:'block',background:'var(--bg-hover)',padding:'4px 8px',borderRadius:4,marginTop:4}}>/tmp/ingest.log</code>
          <code style={{display:'block',background:'var(--bg-hover)',padding:'4px 8px',borderRadius:4,marginTop:4}}>/tmp/api.log</code>
          <code style={{display:'block',background:'var(--bg-hover)',padding:'4px 8px',borderRadius:4,marginTop:4}}>/tmp/frontend.log</code>
        </p>
      </div>}

      <button onClick={()=>{setApiKey('');sessionStorage.removeItem('api_key')}}
        style={{marginTop:20,padding:'8px 16px',background:'transparent',border:'1px solid var(--danger)',color:'var(--danger)',borderRadius:8,cursor:'pointer',fontSize:13}}>
        退出登录
      </button>
    </div>
  );
}
