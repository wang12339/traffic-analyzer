import React, { useEffect, useState } from 'react';

export function HttpView() {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    const load = async () => {
      try { const r = await fetch('/api/http'); const j = await r.json(); if (j.success) setData(j.data); }
      catch {}
    }; load(); const iv = setInterval(load, 5000); return () => clearInterval(iv);
  }, []);
  return (
    <div>
      <div style={{background:'var(--bg-card)',borderRadius:12,border:'1px solid var(--border)',padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,marginBottom:8}}>🔓 HTTP/HTTPS 解密流量</h3>
        <p style={{fontSize:12,color:'var(--text-secondary)',marginBottom:8}}>通过 mitmproxy 解密的 HTTP 请求。HTTPS 需要安装 CA 证书。</p>
        <div style={{fontSize:12,color:'#f59e0b',background:'#2a2000',padding:'8px 12px',borderRadius:6}}>
          💡 安装 CA 证书以解密 HTTPS：
          <code style={{display:'block',marginTop:4,padding:'4px 8px',background:'#000',borderRadius:4}}>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem</code>
        </div>
      </div>
      {data.map((r:any,i:number) => (
        <div key={i} style={{display:'flex',justifyContent:'space-between',padding:'8px 14px',fontSize:13,background:'var(--bg-card)',borderBottom:'1px solid var(--border)',borderRadius:i===0?8:0}}>
          <div style={{overflow:'hidden',flex:1}}>
            <span style={{background:'var(--accent)',color:'#fff',padding:'1px 6px',borderRadius:3,fontSize:11,marginRight:8}}>{r.method}</span>
            <span style={{color:'var(--text-secondary)'}}>{r.host}</span>
            <span style={{fontSize:12,marginLeft:4}}>{r.path?.substring(0,60)}</span>
          </div>
          <span style={{color:r.status_code>=200&&r.status_code<300?'var(--success)':'var(--warning)'}}>{r.status_code||'...'}</span>
        </div>
      ))}
      {data.length===0 && <div style={{padding:40,textAlign:'center',color:'var(--text-secondary)'}}>暂无 HTTP 解密数据。启动 mitmproxy 后通过代理发请求。</div>}
    </div>
  );
}
