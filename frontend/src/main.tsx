import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// 全局 fetch 拦截：自动注入 API Key
const _origFetch = window.fetch.bind(window);
window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  const apiKey = sessionStorage.getItem('api_key');
  if (apiKey) {
    const headers = new Headers(init?.headers);
    headers.set('X-API-Key', apiKey);
    init = { ...init, headers };
  }
  return _origFetch(input, init);
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
