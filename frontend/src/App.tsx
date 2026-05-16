import React, { useState, useEffect } from 'react';
import { ConfigProvider, Layout, Menu, Typography, Select, Tag } from 'antd';
import {
  DashboardOutlined, RadarChartOutlined, AppstoreOutlined,
  WechatOutlined, LinkOutlined, WarningOutlined,
  SettingOutlined, ClockCircleOutlined,
  GlobalOutlined, MenuFoldOutlined, MenuUnfoldOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import { cyberpunkDark } from './theme';
import { useApi } from './hooks/useApi';
import { getStats } from './utils/api';

// Pages
import { DashboardPage } from './components/DashboardPage';
import { InsightsBoard } from './components/InsightsBoard';
import { OverviewFull } from './components/OverviewFull';
import { AppView } from './components/AppView';
import { DeviceDetail } from './components/DeviceDetail';
import { AlertsView } from './components/AlertsView';
import { HttpView } from './components/HttpView';
import { AdminPanel } from './components/AdminPanel';
import { TimelineView } from './components/TimelineView';
import { GeoMapPage } from './components/GeoMapPage';
import { WeChatAnalysis } from './components/WeChatAnalysis';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

type TabKey = 'dashboard' | 'insights' | 'overview' | 'apps' | 'alerts' | 'wechat' | 'http' | 'timeline' | 'geo' | 'admin';

const menuItems = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
  { key: 'insights', icon: <RadarChartOutlined />, label: '洞察' },
  { key: 'overview', icon: <SafetyOutlined />, label: '全景' },
  { key: 'timeline', icon: <ClockCircleOutlined />, label: '时间线' },
  { key: 'apps', icon: <AppstoreOutlined />, label: '应用' },
  { key: 'alerts', icon: <WarningOutlined />, label: '告警' },
  { key: 'wechat', icon: <WechatOutlined />, label: '微信' },
  { key: 'geo', icon: <GlobalOutlined />, label: '地图' },
  { key: 'http', icon: <LinkOutlined />, label: 'TLS/SNI' },
  { key: 'admin', icon: <SettingOutlined />, label: '管理' },
];

export default function App() {
  const [tab, setTab] = useState<TabKey>('dashboard');
  const [since, setSince] = useState('24h');
  const [collapsed, setCollapsed] = useState(false);
  const [detailIp, setDetailIp] = useState<string | null>(null);
  const [uptime, setUptime] = useState(0);
  const [apiKeyInput, setApiKeyInput] = useState(sessionStorage.getItem('api_key') || '');
  const [showKeyPrompt, setShowKeyPrompt] = useState(false);
  const stats = useApi(() => getStats(since), [since], { interval: 8000 });

  // 检测认证状态，未登录时弹出 Key 输入框
  useEffect(() => {
    if (stats.error?.includes('401') || stats.error?.includes('403') || stats.error?.includes('invalid api key')) {
      setShowKeyPrompt(true);
    }
  }, [stats.error]);

  const handleSetApiKey = () => {
    const key = apiKeyInput.trim();
    if (key) {
      sessionStorage.setItem('api_key', key);
      setShowKeyPrompt(false);
      // 强制刷新页面让所有请求带上新 key
      window.location.reload();
    }
  };

  useEffect(() => {
    const fetchUptime = () => {
      fetch('/api/admin/status')
        .then(r => r.json())
        .then(j => { if (j.success) setUptime(j.data.uptime_seconds); })
        .catch(() => {});
    };
    fetchUptime();
    const id = setInterval(fetchUptime, 10000);
    return () => clearInterval(id);
  }, []);

  const fmtUptime = (s: number) => {
    if (s <= 0) return '';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
  };

  const handleDeviceClick = (ip: string) => setDetailIp(ip);

  // If viewing device detail, show it within the layout
  const renderContent = () => {
    if (detailIp) {
      return <DeviceDetail ip={detailIp} onBack={() => setDetailIp(null)} />;
    }
    switch (tab) {
      case 'dashboard': return <DashboardPage />;
      case 'insights': return <InsightsBoard onDeviceClick={handleDeviceClick} />;
      case 'overview': return <OverviewFull />;
      case 'apps': return <AppView since={since} />;
      case 'alerts': return <AlertsView />;
      case 'wechat': return <WeChatAnalysis />;
      case 'http': return <HttpView />;
      case 'timeline': return <TimelineView />;
      case 'geo': return <GeoMapPage />;
      case 'admin': return <AdminPanel />;
      default: return <DashboardPage />;
    }
  };

  // API Key 输入弹窗
  const keyPromptOverlay = showKeyPrompt ? (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(7,10,30,0.95)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: '#131842', borderRadius: 16, padding: 32,
        border: '1px solid #1e3a8a', maxWidth: 400, width: '90%',
      }}>
        <h2 style={{ color: '#e0e8ff', marginBottom: 8, fontSize: 18 }}>认证</h2>
        <p style={{ color: '#8892c0', fontSize: 13, marginBottom: 20 }}>
          请输入 API Key 以访问流量分析系统
        </p>
        <input
          type="password"
          value={apiKeyInput}
          onChange={e => setApiKeyInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSetApiKey()}
          placeholder="输入 API Key"
          style={{
            width: '100%', padding: '10px 14px', borderRadius: 8,
            border: '1px solid #1e3a8a', background: '#0a0e27',
            color: '#e0e8ff', fontSize: 14, outline: 'none',
            boxSizing: 'border-box', marginBottom: 16,
          }}
          autoFocus
        />
        <button
          onClick={handleSetApiKey}
          style={{
            width: '100%', padding: '10px', borderRadius: 8,
            border: 'none', background: '#6366f1', color: '#fff',
            fontSize: 14, fontWeight: 600, cursor: 'pointer',
          }}
        >
          确认
        </button>
      </div>
    </div>
  ) : null;

  const statusColor = stats.error ? 'red' : stats.data ? 'green' : 'yellow';
  const statusText = stats.error ? '连接异常' : stats.data ? '运行中' : '连接中...';

  return (
    <ConfigProvider theme={cyberpunkDark}>
      <Layout style={{ minHeight: '100vh' }}>
        <Sider
          collapsible
          collapsed={collapsed}
          onCollapse={setCollapsed}
          width={200}
          collapsedWidth={56}
          trigger={null}
          style={{
            position: 'fixed',
            left: 0,
            top: 0,
            bottom: 0,
            zIndex: 100,
            borderRight: '1px solid rgba(30,58,138,0.3)',
            overflow: 'auto',
          }}
        >
          {/* Logo area */}
          <div style={{
            height: 56,
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            padding: collapsed ? 0 : '0 16px',
            borderBottom: '1px solid rgba(30,58,138,0.2)',
            gap: 8,
          }}>
            <span style={{ fontSize: 22 }}>🌐</span>
            {!collapsed && (
              <Text strong style={{ fontSize: 15, color: '#e0e8ff', whiteSpace: 'nowrap' }}>
                流量分析系统
              </Text>
            )}
          </div>

          {/* Navigation */}
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[tab]}
            items={menuItems}
            onClick={({ key }) => {
              setTab(key as TabKey);
              setDetailIp(null);
            }}
            style={{ borderRight: 'none', marginTop: 4 }}
          />
        </Sider>

        <Layout style={{ marginLeft: collapsed ? 56 : 200, transition: 'margin-left 0.2s' }}>
          {/* Header */}
          <Header style={{
            padding: '0 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            height: 56,
            borderBottom: '1px solid rgba(30,58,138,0.2)',
            position: 'sticky',
            top: 0,
            zIndex: 50,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              {/* Collapse toggle */}
              <span
                onClick={() => setCollapsed(!collapsed)}
                style={{ fontSize: 18, cursor: 'pointer', color: '#8892c0', display: 'flex', alignItems: 'center' }}
              >
                {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              </span>

              {/* Page title */}
              <Text strong style={{ fontSize: 14, color: '#e0e8ff' }}>
                {menuItems.find(m => m.key === tab)?.label || '仪表盘'}
              </Text>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              {/* Stats summary */}
              {stats.data && (
                <Text style={{ fontSize: 12, color: '#8892c0' }}>
                  {stats.data.total_flows.toLocaleString()} 流 · {stats.data.flows_per_sec.toFixed(1)}/s
                </Text>
              )}

              {/* Uptime */}
              {uptime > 0 && (
                <Tag icon={<ClockCircleOutlined />} style={{ fontSize: 11, borderRadius: 8, margin: 0, border: '1px solid rgba(99,102,241,0.3)' }}>
                  运行 {fmtUptime(uptime)}
                </Tag>
              )}

              {/* Time range */}
              <Select
                value={since}
                onChange={setSince}
                size="small"
                style={{ width: 100 }}
                options={[
                  { value: '15m', label: '15分钟' },
                  { value: '30m', label: '30分钟' },
                  { value: '1h', label: '1小时' },
                  { value: '24h', label: '24小时' },
                ]}
              />

              {/* Status indicator */}
              <Tag color={statusColor} style={{ fontSize: 11, borderRadius: 8, margin: 0 }}>
                {statusText}
              </Tag>
            </div>
          </Header>

          {/* Content */}
          <Content style={{
            padding: 20,
            overflow: 'auto',
            height: 'calc(100vh - 56px)',
            background: '#070a1e',
          }}>
            {renderContent()}
          </Content>
        </Layout>
      </Layout>
      {keyPromptOverlay}
    </ConfigProvider>
  );
}
