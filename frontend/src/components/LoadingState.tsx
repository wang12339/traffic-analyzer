import React from 'react';

interface LoadingProps {
  message?: string;
}

export function LoadingSpinner({ message = 'Loading...' }: LoadingProps) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: 60, color: 'var(--text-secondary)',
    }}>
      <div className="spinner" style={{
        width: 32, height: 32, border: '3px solid var(--border)',
        borderTopColor: 'var(--accent)', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite', marginBottom: 12,
      }} />
      <span style={{ fontSize: 14 }}>{message}</span>
    </div>
  );
}

interface ErrorStateProps {
  error: string | null;
  onRetry?: () => void;
}

export function ErrorState({ error, onRetry }: ErrorStateProps) {
  if (!error) return null;
  return (
    <div style={{
      padding: 40, textAlign: 'center', color: 'var(--danger)',
      background: 'var(--bg-card)', borderRadius: 12,
      border: '1px solid #3a2020',
    }}>
      <div style={{ fontSize: 32, marginBottom: 8 }}>!</div>
      <div style={{ fontSize: 14, marginBottom: 12 }}>{error}</div>
      {onRetry && (
        <button onClick={onRetry} style={{
          padding: '8px 20px', background: 'var(--accent)', color: '#fff',
          border: 'none', borderRadius: 8, cursor: 'pointer', fontSize: 13,
        }}>
          Retry
        </button>
      )}
    </div>
  );
}

interface EmptyStateProps {
  message?: string;
  icon?: string;
}

export function EmptyState({ message = 'No data available', icon = '--' }: EmptyStateProps) {
  return (
    <div style={{
      padding: 60, textAlign: 'center', color: 'var(--text-secondary)',
    }}>
      <div style={{ fontSize: 40, marginBottom: 8 }}>{icon}</div>
      <div style={{ fontSize: 14 }}>{message}</div>
    </div>
  );
}
