import React, { useState } from 'react';
import { ConfigProvider, Layout, Menu, Typography, Select, Tag } from 'antd';
import {
  DashboardOutlined, RadarChartOutlined, AppstoreOutlined,
  WechatOutlined, LinkOutlined, ApartmentOutlined,
  BellOutlined, SettingOutlined, ClockCircleOutlined,
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
import { HttpView } from './components/HttpView';
import { AdminPanel } from './components/AdminPanel';
import { TopologyView } from './components/TopologyView';
import { AlertsView } from './components/AlertsView';
import { TimelineView } from './components/TimelineView';
import { GeoMapPage } from './components/GeoMapPage';
import { WeChatAnalysis } from './components/WeChatAnalysis';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

type TabKey = 'dashboard' | 'insights' | 'overview' | 'apps' | 'wechat' | 'http' | 'topo' | 'alerts' | 'timeline' | 'geo' | 'admin';

const menuItems = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
  { key: 'insights', icon: <RadarChartOutlined />, label: '洞察' },
  { key: 'overview', icon: <SafetyOutlined />, label: '全景' },
  { key: 'timeline', icon: <ClockCircleOutlined />, label: '时间线' },
  { key: 'apps', icon: <AppstoreOutlined />, label: '应用' },
  { key: 'wechat', icon: <WechatOutlined />, label: '微信' },
  { key: 'geo', icon: <GlobalOutlined />, label: '地图' },
  { key: 'http', icon: <LinkOutlined />, label: 'HTTP' },
  { key: 'topo', icon: <ApartmentOutlined />, label: '拓扑' },
  { key: 'alerts', icon: <BellOutlined />, label: '告警' },
  { key: 'admin', icon: <SettingOutlined />, label: '管理' },
];

export default function App() {
  const [tab, setTab] = useState<TabKey>('dashboard');
  const [since, setSince] = useState('30m');
  const [collapsed, setCollapsed] = useState(false);
  const [detailIp, setDetailIp] = useState<string | null>(null);
  const stats = useApi(() => getStats(since), [since], { interval: 8000 });

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
      case 'wechat': return <WeChatAnalysis />;
      case 'http': return <HttpView />;
      case 'topo': return <TopologyView />;
      case 'alerts': return <AlertsView />;
      case 'timeline': return <TimelineView />;
      case 'geo': return <GeoMapPage />;
      case 'admin': return <AdminPanel />;
      default: return <DashboardPage />;
    }
  };

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
    </ConfigProvider>
  );
}
