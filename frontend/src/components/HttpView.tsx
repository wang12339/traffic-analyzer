import React, { useMemo } from 'react';
import { Card, Row, Col, Statistic, Tag, Table, Typography } from 'antd';
import { SafetyOutlined, LinkOutlined, KeyOutlined, GlobalOutlined } from '@ant-design/icons';
import { getFlows, getSni } from '../utils/api';
import { useApi } from '../hooks/useApi';
import { LoadingSpinner, ErrorState, EmptyState } from './LoadingState';

const { Text } = Typography;

export function HttpView() {
  const sni = useApi(() => getSni('24h'), [], { interval: 15000 });
  const flows = useApi(() => getFlows({ limit: 300, since: '24h' }), [], { interval: 15000 });

  // Filter TLS flows (those with SNI)
  const tlsFlows = useMemo(() => {
    if (!flows.data) return [];
    return (flows.data as any[]).filter(f => f.sni && f.sni !== '');
  }, [flows.data]);

  // TLS version distribution
  const tlsVersions = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of tlsFlows) {
      const v = f.tls_version || 'Unknown';
      map.set(v, (map.get(v) || 0) + 1);
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [tlsFlows]);

  // Cipher suite usage
  const ciphers = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of tlsFlows) {
      if (f.server_cipher_suite && f.server_cipher_suite > 0) {
        const c = String(f.server_cipher_suite);
        map.set(c, (map.get(c) || 0) + 1);
      }
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  }, [tlsFlows]);

  // Top SNI
  const topSni = useMemo(() => {
    if (!sni.data) return [];
    return (sni.data as any[]).slice(0, 20);
  }, [sni.data]);

  const totalTls = tlsFlows.length;
  const totalSni = topSni.length;

  const cipherNames: Record<string, string> = {
    '4865': 'TLS_AES_128_GCM_SHA256',
    '4866': 'TLS_AES_256_GCM_SHA384',
    '4867': 'TLS_CHACHA20_POLY1305_SHA256',
    '49195': 'TLS_ECDHE_ECDSA_AES128_GCM',
    '49196': 'TLS_ECDHE_ECDSA_AES256_GCM',
    '49199': 'TLS_ECDHE_RSA_AES128_GCM',
    '49200': 'TLS_ECDHE_RSA_AES256_GCM',
    '52392': 'TLS_ECDHE_ECDSA_CHACHA20',
    '52393': 'TLS_ECDHE_RSA_CHACHA20',
  };

  const columns = [
    { title: '域名', dataIndex: 'sni', key: 'sni', render: (v: string) => <Text copyable style={{ fontSize: 12 }}>{v}</Text> },
    { title: '次数', dataIndex: 'count', key: 'count', width: 70 },
    { title: '设备', dataIndex: 'clients', key: 'clients', width: 60 },
  ];

  if (sni.loading && !sni.data) return <LoadingSpinner message="加载 TLS 数据..." />;
  if (sni.error) return <ErrorState error={sni.error} onRetry={sni.refetch} />;

  return (
    <div>
      {/* KPI */}
      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ borderLeft: '3px solid #6366f1' }}>
            <Statistic title="TLS 连接" value={totalTls} prefix={<SafetyOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ borderLeft: '3px solid #22c55e' }}>
            <Statistic title="SNI 域名" value={totalSni} prefix={<GlobalOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ borderLeft: '3px solid #f59e0b' }}>
            <Statistic title="TLS 版本" value={tlsVersions.length} prefix={<KeyOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ borderLeft: '3px solid #60a5fa' }}>
            <Statistic title="加密套件" value={ciphers.length} prefix={<LinkOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        {/* TLS Version Distribution */}
        <Col xs={24} md={8}>
          <Card title="TLS 版本分布" size="small">
            {tlsVersions.length === 0 ? <EmptyState message="暂无数据" /> :
              tlsVersions.map(([v, c]) => {
                const pct = totalTls > 0 ? (c / totalTls * 100) : 0;
                return (
                  <div key={v} style={{ marginBottom: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                      <Tag color="processing" style={{ fontSize: 11 }}>{v}</Tag>
                      <span style={{ color: '#8892c0' }}>{c}次 ({pct.toFixed(0)}%)</span>
                    </div>
                    <div style={{ height: 4, background: 'rgba(99,102,241,0.1)', borderRadius: 2 }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: '#6366f1', borderRadius: 2 }} />
                    </div>
                  </div>
                );
              })
            }
          </Card>
        </Col>

        {/* Cipher Suites */}
        <Col xs={24} md={8}>
          <Card title="加密套件" size="small">
            {ciphers.length === 0 ? <EmptyState message="暂无数据" /> :
              ciphers.map(([code, count]) => {
                const name = cipherNames[code] || `0x${Number(code).toString(16).padStart(4, '0')}`;
                const pct = totalTls > 0 ? (count / totalTls * 100) : 0;
                return (
                  <div key={code} style={{ marginBottom: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 1 }}>
                      <Text style={{ fontSize: 11 }} ellipsis={{ tooltip: name }}>{name}</Text>
                      <span style={{ color: '#8892c0' }}>{count}</span>
                    </div>
                    <div style={{ height: 3, background: 'rgba(99,102,241,0.1)', borderRadius: 2 }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: '#818cf8', borderRadius: 2 }} />
                    </div>
                  </div>
                );
              })
            }
          </Card>
        </Col>

        {/* Recent TLS Flows */}
        <Col xs={24} md={8}>
          <Card title="最近 TLS 握手" size="small" bodyStyle={{ padding: 0 }}>
            {tlsFlows.length === 0 ? <div style={{ padding: 20 }}><EmptyState message="暂无数据" /></div> :
              <div style={{ maxHeight: 320, overflow: 'auto' }}>
                {tlsFlows.slice(0, 20).map((f: any, i: number) => (
                  <div key={i} style={{ padding: '6px 12px', borderBottom: '1px solid rgba(30,58,138,0.1)', fontSize: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Text style={{ fontSize: 11 }} ellipsis={{ tooltip: f.sni }}>{f.sni}</Text>
                      <Tag style={{ fontSize: 10, lineHeight: '16px', padding: '0 4px' }}>{f.tls_version || 'TLS?'}</Tag>
                    </div>
                    <div style={{ color: '#8892c0', fontSize: 11, marginTop: 1 }}>
                      {f.dst_ip}:{f.dst_port} · {f.app_name || '-'}
                    </div>
                  </div>
                ))}
              </div>
            }
          </Card>
        </Col>
      </Row>

      {/* SNI Ranking Table */}
      <Card title="📊 域名访问排行" size="small" bodyStyle={{ padding: 0 }}>
        <Table
          dataSource={topSni}
          columns={columns}
          rowKey="sni"
          size="small"
          pagination={{ pageSize: 10, size: 'small' }}
          locale={{ emptyText: '暂无 SNI 数据' }}
        />
      </Card>
    </div>
  );
}
