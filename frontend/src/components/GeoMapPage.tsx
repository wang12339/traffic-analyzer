import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Card, Row, Col, Statistic, Spin, Tag, Empty, Alert } from 'antd';
import { GlobalOutlined, ApiOutlined, EnvironmentOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';
import { getFlows } from '../utils/api';
import { useApi } from '../hooks/useApi';
import { resolveFlowIPs } from '../utils/geo';
import { fmt } from './KpiBox';

interface FlowPoint {
  name: string;
  value: [number, number, number];
  ip: string;
  country: string;
}

interface FlowLine {
  coords: [[number, number], [number, number]];
  value: number;
}

export function GeoMapPage() {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);
  const [mapReady, setMapReady] = useState(false);
  const [mapError, setMapError] = useState('');
  const [points, setPoints] = useState<FlowPoint[]>([]);
  const [lines, setLines] = useState<FlowLine[]>([]);
  const [stats, setStats] = useState({ countries: 0, ips: 0, flows: 0 });

  const flows = useApi(() => getFlows({ limit: 200, since: '24h' }), [], { interval: 30000 });

  // Load world map GeoJSON from local file
  useEffect(() => {
    fetch('/data/world.json')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(geo => {
        echarts.registerMap('world', geo as any);
        setMapReady(true);
      })
      .catch(err => {
        setMapError(`地图数据加载失败: ${err.message}`);
        setMapReady(true); // proceed anyway
      });
  }, []);

  // Process flows into geo points
  useEffect(() => {
    if (!flows.data || !flows.data.length) {
      return;
    }

    const flowData = flows.data as any[];
    resolveFlowIPs(flowData).then(geoMap => {
      const pointMap = new Map<string, FlowPoint>();
      const lineData: FlowLine[] = [];
      let totalFlows = 0;

      for (const f of flowData) {
        const loc = geoMap.get(f.dst_ip);
        if (!loc) continue;
        totalFlows++;

        const key = `${loc.lat},${loc.lon}`;
        const existing = pointMap.get(key);
        const bytes = f.bytes_up + f.bytes_down || 1;
        if (existing) {
          existing.value[2] += bytes;
        } else {
          pointMap.set(key, {
            name: `${loc.city}, ${loc.country}`,
            value: [loc.lon, loc.lat, bytes],
            ip: f.dst_ip,
            country: loc.country,
          });
        }

        // Arc line from approximate origin to destination
        const origin: [number, number] = [
          loc.lon - (Math.random() * 30 + 10),
          loc.lat + (Math.random() * 15 - 7),
        ];
        lineData.push({
          coords: [origin, [loc.lon, loc.lat]],
          value: bytes,
        });
      }

      const sortedPoints = [...pointMap.values()].sort((a, b) => b.value[2] - a.value[2]);
      const sortedLines = lineData.sort((a, b) => b.value - a.value).slice(0, 80);

      setPoints(sortedPoints);
      setLines(sortedLines);
      setStats({
        countries: new Set(sortedPoints.map(p => p.country)).size,
        ips: sortedPoints.length,
        flows: totalFlows,
      });
    }).catch(() => {
      // ignore
    });
  }, [flows.data]);

  // Render chart
  const renderChart = useCallback(() => {
    if (!chartRef.current || !mapReady || points.length === 0) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, undefined, { renderer: 'canvas' });
    }
    const chart = chartInstance.current;

    const maxVal = Math.max(...points.map(p => p.value[2]), 1);
    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: (params: any) => {
          if (params.seriesType === 'scatter') {
            return `<strong>${params.data?.name || 'Unknown'}</strong><br/>📡 ${params.data?.ip || ''}<br/>📦 ${fmt(params.data?.value[2] || 0)}`;
          }
          return '';
        },
        backgroundColor: 'rgba(19,24,66,0.95)',
        borderColor: '#1e3a8a',
        borderWidth: 1,
        textStyle: { color: '#e0e8ff', fontSize: 12 },
      },
      visualMap: {
        min: 0,
        max: maxVal,
        text: ['高', '低'],
        textStyle: { color: '#8892c0' },
        inRange: { color: ['rgba(99,102,241,0.2)', '#6366f1', '#818cf8', '#a78bfa'] },
        calculable: true,
        dimension: 2,
        left: 16,
        bottom: 16,
        itemWidth: 12,
        itemHeight: 80,
      },
      geo: {
        map: 'world',
        roam: true,
        zoom: 1.1,
        center: [15, 10],
        itemStyle: {
          areaColor: '#0f1440',
          borderColor: '#1e3a8a',
          borderWidth: 0.5,
          shadowBlur: 8,
          shadowColor: 'rgba(99,102,241,0.08)',
        },
        emphasis: {
          itemStyle: { areaColor: '#1a2450' },
          label: { color: '#818cf8', fontSize: 10 },
        },
      },
      series: [
        {
          name: '流量连接',
          type: 'lines',
          coordinateSystem: 'geo',
          data: lines.map(l => ({
            coords: l.coords,
            value: l.value,
          })),
          lineStyle: {
            color: '#6366f1',
            opacity: 0.2,
            curveness: 0.3,
            width: 1,
          },
          effect: {
            show: true,
            period: 5,
            trailLength: 0.08,
            symbol: 'circle',
            symbolSize: 3,
            color: '#818cf8',
          },
          zlevel: 1,
        },
        {
          name: '目标',
          type: 'scatter',
          coordinateSystem: 'geo',
          data: points.map(p => ({
            name: p.name,
            value: p.value,
            ip: p.ip,
          })),
          symbol: 'circle',
          symbolSize: (val: any) => Math.max(6, Math.min(22, Math.log2((val[2] || 1) / 1000 + 1) * 3)),
          itemStyle: {
            color: '#818cf8',
            shadowBlur: 6,
            shadowColor: 'rgba(99,102,241,0.3)',
          },
          emphasis: {
            itemStyle: { shadowBlur: 12, shadowColor: 'rgba(99,102,241,0.5)' },
            label: { show: true, color: '#e0e8ff', fontSize: 11, formatter: (p: any) => p.data?.name || '' },
          },
          zlevel: 2,
        },
      ],
    };

    chart.setOption(option, true);

    const resize = () => chart.resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [mapReady, points, lines]);

  useEffect(() => {
    const cleanup = renderChart();
    return () => { cleanup?.(); };
  }, [renderChart]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    };
  }, []);

  const loading = !flows.data && flows.loading;
  const hasData = points.length > 0;

  return (
    <div>
      <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
        <Col xs={8} sm={6} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #6366f1' }}>
            <Statistic title="目标国家" value={stats.countries} prefix={<GlobalOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={8} sm={6} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #22c55e' }}>
            <Statistic title="目标城市" value={stats.ips} prefix={<EnvironmentOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={8} sm={6} md={4}>
          <Card size="small" style={{ borderLeft: '3px solid #f59e0b' }}>
            <Statistic title="连接数" value={stats.flows} prefix={<ApiOutlined />} valueStyle={{ fontSize: 20, fontWeight: 700 }} />
          </Card>
        </Col>
        <Col xs={24} sm={6} md={12}>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center', height: '100%', padding: '0 8px' }}>
            {points.slice(0, 10).map(p => (
              <Tag key={p.ip} color="processing" style={{ fontSize: 11, margin: 0 }}>{p.country}</Tag>
            ))}
            {points.length > 10 && <Tag style={{ fontSize: 11 }}>+{points.length - 10}</Tag>}
          </div>
        </Col>
      </Row>

      <Card size="small" bodyStyle={{ padding: 0, position: 'relative', minHeight: 400 }}>
        {mapError && <Alert message={mapError} type="warning" showIcon style={{ margin: 12 }} />}
        {loading && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 500 }}>
            <Spin tip="加载流量数据..." />
          </div>
        )}
        {!loading && mapReady && !mapError && !hasData && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 500 }}>
            <Empty description="暂无地理数据，请确保有外网流量" />
          </div>
        )}
        {!loading && !mapReady && !mapError && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 500 }}>
            <Spin tip="加载地图数据..." />
          </div>
        )}
        <div ref={chartRef} style={{ width: '100%', height: 560, display: hasData ? 'block' : 'none' }} />
      </Card>
    </div>
  );
}
