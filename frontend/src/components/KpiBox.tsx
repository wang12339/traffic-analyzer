export function fmt(b: number): string {
  if (b >= 1e9) return (b/1e9).toFixed(1)+'G';
  if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
  if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
  return b+'B';
}

export function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleTimeString('zh-CN', {hour12:false}); } catch { return ts; }
}

export const TYPE_ICONS: Record<string, string> = {
  'iPhone/iPad': '📱', 'Mac': '💻', 'Apple Device': '🍎',
  'Xiaomi': '📱', 'Huawei': '📱', 'Android Device': '🤖',
  'Windows PC': '🖥️', 'Unknown': '❓',
};

export function KpiBox({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div style={{background:'var(--bg-card)', borderRadius:10, border:'1px solid var(--border)', padding:'14px 16px'}}>
      <div style={{fontSize:12, color:'var(--text-secondary)', marginBottom:4}}>{label}</div>
      <div style={{fontSize:22, fontWeight:700, color: color || 'var(--text-primary)'}}>{value}</div>
    </div>
  );
}
