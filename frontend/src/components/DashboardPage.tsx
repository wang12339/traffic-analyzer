import React, { useState } from 'react';
import { Card, Row, Col, Table, Tag, Statistic, Typography, Progress } from 'antd';
import {
  ArrowUpOutlined, ArrowDownOutlined,
  ApiOutlined, CloudServerOutlined, LaptopOutlined,
  ThunderboltOutlined, RiseOutlined, GlobalOutlined,
} from '@ant-design/icons';
import { AreaChart, Area, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { useApi } from '../hooks/useApi';
import { getStats, getTrends, getApps, getDevices } from '../utils/api';
import { fmt } from './KpiBox';

const { Text } = Typography;
const COLORS = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#60a5fa', '#a78bfa', '#34d399', '#fb923c'];

export function DashboardPage() {
  const [since] = useState('24h');
  const stats = useApi(() => getStats(since), [since], { interval: 8000 });
  const trends = useApi(() => getTrends(since), [since], { interval: 15000 });
  const apps = useApi(() => getApps(since), [since], { interval: 15000 });
  const devices = useApi(() => getDevices(since), [since], { interval: 15000 });

  const s = stats.data;
  const trendData = (trends.data || []).slice(-24);
  const appData = (apps.data || [])
    .filter((x: any) => x.app_name && x.app_name !== 'Unknown')
    .sort((a: any, b: any) => b.flow_count - a.flow_count)
    .slice(0, 12);
  const deviceData = (devices.data || [])
    .sort((a: any, b: any) => b.bytes_total - a.bytes_total)
    .slice(0, 10);

  const totalProto = (s?.tcp_flows || 0) + (s?.udp_flows || 0);
  const tcpPct = totalProto > 0 ? ((s?.tcp_flows || 0) / totalProto * 100) : 0;
  const udpPct = totalProto > 0 ? ((s?.udp_flows || 0) / totalProto * 100) : 0;

  const protoData = [
    { name: 'TCP', value: s?.tcp_flows || 0 },
    { name: 'UDP', value: s?.udp_flows || 0 },
  ].filter(d => d.value > 0);

  const appColors = appData.map((_: any, i: number) => COLORS[i % COLORS.length]);

  const deviceColumns = [
    { title: 'IP', dataIndex: 'src_ip', key: 'ip', render: (v: string) => <Text code style={{ fontSize: 12 }}>{v}</Text> },
    { title: '流量', dataIndex: 'bytes_total', key: 'bytes', render: (v: number) => fmt(v), width: 90 },
    { title: '流数', dataIndex: 'flows', key: 'flows', width: 70 },
    { title: '应用', dataIndex: 'app_names', key: 'apps', render: (v: string) => (
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {(v || '').split(',').slice(0, 3).map((a: string) =>
          a ? <Tag key={a} style={{ fontSize: 10, lineHeight: '18px', padding: '0 6px' }}>{a}</Tag> : null
        )}
      </div>
    )},
    { title: '域名', dataIndex: 'sni_count', key: 'sni', width: 70, render: (v: number) => v || 0 },
  ];

  return (
    <div>
      {/* KPI Cards */}
      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #6366f1' }}>
            <Statistic title="总流数" value={s?.total_flows || 0} prefix={<ApiOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #60a5fa' }}>
            <Statistic title="流量" value={((s?.total_bytes || 0) / 1024 / 1024 / 1024).toFixed(2)} suffix="GB" prefix={<CloudServerOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #22c55e' }}>
            <Statistic title="设备" value={s?.unique_devices || 0} prefix={<LaptopOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #f59e0b' }}>
            <Statistic title="吞吐量" value={(s?.throughput_mbps || 0).toFixed(1)} suffix="Mbps" prefix={<ThunderboltOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #a78bfa' }}>
            <Statistic title="应用" value={s?.active_apps || 0} prefix={<RiseOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #34d399' }}>
            <Statistic title="域名" value={s?.unique_snis || 0} prefix={<GlobalOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
      </Row>

      {/* Charts Row */}
      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        <Col xs={24} md={14}>
          <Card title="流量趋势" size="small" extra={<Text style={{ fontSize: 11, color: '#8892c0' }}>{since}</Text>}>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(99,102,241,0.08)" />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#8892c0' }} tickFormatter={(v: string) => {
                  try { return new Date(v).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false }); } catch { return v; }
                }} />
                <YAxis tick={{ fontSize: 10, fill: '#8892c0' }} />
                <Tooltip
                  contentStyle={{ background: '#1a1f4e', border: '1px solid #1e3a8a', borderRadius: 8, fontSize: 12 }}
                  labelFormatter={(v: string) => { try { return new Date(v).toLocaleString('zh-CN'); } catch { return v; } }}
                />
                <Area type="monotone" dataKey="flows" stroke="#6366f1" fill="url(#flowGradient)" strokeWidth={2} name="流数" />
                <Area type="monotone" dataKey="bytes" stroke="#60a5fa" fill="none" strokeWidth={1.5} name="字节" />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col xs={12} md={5}>
          <Card title="协议分布" size="small">
            <div style={{ padding: '8px 0' }}>
              <div style={{ display: 'flex', gap: 0, height: 10, borderRadius: 5, overflow: 'hidden', marginBottom: 12 }}>
                <div style={{ flex: Math.max(tcpPct, 1), background: '#6366f1' }} title={`TCP ${tcpPct.toFixed(0)}%`} />
                <div style={{ flex: Math.max(udpPct, 1), background: '#22c55e' }} title={`UDP ${udpPct.toFixed(0)}%`} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: 12 }}>
                <span><span style={{ color: '#6366f1', fontWeight: 700 }}>●</span> TCP {s?.tcp_flows?.toLocaleString()} ({tcpPct.toFixed(0)}%)</span>
                <span><span style={{ color: '#22c55e', fontWeight: 700 }}>●</span> UDP {s?.udp_flows?.toLocaleString()} ({udpPct.toFixed(0)}%)</span>
              </div>
            </div>
            {protoData.length > 0 && (
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={protoData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} dataKey="value" stroke="none">
                    {protoData.map((_, i) => (
                      <Cell key={i} fill={i === 0 ? '#6366f1' : '#22c55e'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1a1f4e', border: '1px solid #1e3a8a', borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
        <Col xs={12} md={5}>
          <Card title="实时速率" size="small">
            <div style={{ padding: '12px 0' }}>
              <Statistic
                title="当前流/秒"
                value={s?.flows_per_sec?.toFixed(1) || 0}
                suffix="/s"
                valueStyle={{ fontSize: 28, fontWeight: 700, color: '#6366f1' }}
              />
              <div style={{ marginTop: 16 }}>
                <Text style={{ fontSize: 12, color: '#8892c0' }}>网络负载</Text>
                <Progress
                  percent={Math.min(((s?.throughput_mbps || 0) / 100) * 100, 100)}
                  strokeColor={{ from: '#22c55e', to: '#6366f1' }}
                  trailColor="rgba(99,102,241,0.1)"
                  size="small"
                  format={() => `${(s?.throughput_mbps || 0).toFixed(1)} Mbps`}
                />
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      {/* Tables Row */}
      <Row gutter={[12, 12]}>
        <Col xs={24} md={8}>
          <Card title="📱 应用排行" size="small" bodyStyle={{ padding: 0 }}>
            <div style={{ padding: '8px 12px' }}>
              {appData.map((a: any) => {
                const pct = s?.total_flows ? (a.flow_count / s.total_flows * 100) : 0;
                return (
                  <div key={a.app_id + '-' + a.app_name} style={{ marginBottom: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                      <span>{a.app_name}</span>
                      <span style={{ color: '#8892c0' }}>{a.flow_count}次</span>
                    </div>
                    <div style={{ height: 4, background: 'rgba(99,102,241,0.1)', borderRadius: 2 }}>
                      <div style={{ height: '100%', width: `${Math.min(pct * 3, 100)}%`, background: '#6366f1', borderRadius: 2, transition: 'width 0.5s ease' }} />
                    </div>
                  </div>
                );
              })}
              {appData.length === 0 && <div style={{ textAlign: 'center', padding: 20, color: '#8892c0', fontSize: 12 }}>暂无应用数据</div>}
            </div>
          </Card>
        </Col>
        <Col xs={24} md={16}>
          <Card title="📡 设备排行" size="small" bodyStyle={{ padding: 0 }}>
            <Table
              dataSource={deviceData}
              columns={deviceColumns}
              rowKey="src_ip"
              size="small"
              pagination={false}
              locale={{ emptyText: '暂无设备数据' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
