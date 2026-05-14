# 流量分析系统 · Traffic Analyzer

全栈网络流量分析平台。基于 **Rust** + **React** + **ClickHouse**，在 OpenWrt 路由器上抓包，实时识别设备、应用、异常行为。

## 架构

```
┌──────────────┐    TCP (bincode)    ┌────────────┐    SQL     ┌─────────┐
│  Agent       │───────────────────▶│  Ingest    │───────────▶│ CH  🗄️ │
│  (Rust,      │                    │  (Rust)    │            └─────────┘
│   AF_PACKET) │                    │  流聚合     │               │
└──────────────┘                    │  L7 分类    │               │
                                    │  ClickHouse │               │
┌──────────────┐    UDP (JSON)      └────────────┘               │
│  MITM Agent  │───────────────────▶                             │
│  (Python)    │                                                │
└──────────────┘                                                │
                                                                ▼
┌──────────────────────────────────────────────────────────┐
│                     API (Actix-web)                       │
│   /stats /flows /apps /devices /dns /sni /trends          │
│   /insights /live /topology /alerts /wechat /http         │
│   /device/{ip} /agent/start|stop|restart /export/csv      │
└──────────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│              Frontend · React 19 + Recharts               │
│   概览 · 实时 · 拓扑 · 设备 · 应用 · DNS · SNI · 时间线   │
│   洞见 · 警报 · 微信分析 · HTTP 会话 · 管理面板           │
└──────────────────────────────────────────────────────────┘
```

## 快速开始

### 依赖

- Rust 2024 edition
- [ClickHouse](https://clickhouse.com/)（>= 23.x）
- Node.js >= 18

### 1. 编译

```bash
cd traffic-analyzer
cargo build --release
cd frontend && npm install && npm run build && cd ..
```

### 2. 启动 ClickHouse

```bash
clickhouse server --daemon
```

### 3. 启动后端服务

```bash
# 数据接入 (TCP :9100, UDP :2055)
RUST_LOG=info ./target/release/ingest &

# API 服务 (:8970)
RUST_LOG=info ./target/release/api &
```

### 4. 启动前端

```bash
cd frontend && npm run dev
```

打开 `http://localhost:3001`

### 5. 部署路由器 Agent

在 OpenWrt 路由器上运行：

```bash
# 将 agent 复制到路由器
scp target/release/agent root@192.168.1.1:/root/

# 在路由器上执行
./agent --interface br-lan --ingest <电脑IP>:9100
```

### 一键部署

```bash
./deploy/deploy.sh
```

或使用桌面快捷方式（macOS）：双击 `流量分析系统.command` 开关系统。

## API 示例

```bash
# 概览统计
curl http://localhost:8970/api/stats

# 实时流量
curl http://localhost:8970/api/live

# 设备洞察
curl http://localhost:8970/api/insights

# 微信分析
curl http://localhost:8970/api/analysis/wechat

# 拓扑
curl http://localhost:8970/api/topology

# CSV 导出
curl "http://localhost:8970/api/export/csv?since=1h"
```

完整 API 文档见 [API.md](API.md)（可选）。

## 应用分类

内置 130+ 条规则，覆盖常见应用的 SNI/DNS 识别：

| 类别 | 应用 |
|------|------|
| AI | ChatGPT, Claude, DeepSeek, Gemini, Kimi, 通义千问, Coze |
| 视频 | YouTube, Netflix, 抖音/TikTok, Bilibili, 爱奇艺, 腾讯视频, 优酷, Twitch |
| 社交 | 微信, 微博, 小红书, 知乎, Instagram, X/Twitter, Telegram, Discord, QQ |
| 音乐 | QQ音乐, 网易云音乐, Spotify, 酷狗, 酷我 |
| 购物 | 淘宝/天猫, 京东, 拼多多, Amazon, 美团 |
| 云服务 | 阿里云, 腾讯云, AWS, GCP, Azure, Cloudflare |
| 系统 | Windows Update, Apple 推送, 小米 IoT, 华为 HMS |

## 设备识别

基于 MAC OUI + SNI/DNS 模式 + User-Agent 的多维设备指纹识别，支持：
- Xiaomi / Redmi
- iPhone / iPad / Mac
- Huawei
- Samsung Galaxy
- Windows PC
- OpenWrt 路由器
- Clash/Stash 代理客户端

## 异常检测

行为基线 + 实时偏差分析，检测：
- 设备突然访问大量新域名
- 非典型应用使用模式
- 流量突增
- 风险评分 0-100

## 项目结构

```
traffic-analyzer/
├── agent/              # 路由器抓包代理 (Rust, AF_PACKET)
├── ingest/             # 数据接入 & 流处理 (Rust)
│   └── src/
│       ├── flow_agg.rs     # 流聚合引擎
│       ├── classifier.rs   # 应用分类
│       ├── storage.rs      # ClickHouse 存储层
│       ├── tcp_reasm.rs    # TCP 重组
│       ├── tls_parser.rs   # TLS SNI 解析
│       ├── http_parser.rs  # HTTP 解析
│       └── dns_parser.rs   # DNS 解析
├── api/                # REST API 服务 (Actix-web)
│   └── src/routes/
│       ├── queries.rs      # 数据查询
│       ├── analysis.rs     # 分析 & 洞见
│       └── agent.rs        # Agent 管理
├── traffic-core/       # 共享类型 & 分类规则
├── frontend/           # React + TypeScript 仪表盘
│   └── src/components/
│       ├── OverviewFull.tsx
│       ├── InsightsBoard.tsx
│       ├── TopologyView.tsx
│       ├── AlertsView.tsx
│       ├── WeChatAnalysis.tsx
│       └── ...
├── mitm_agent.py       # HTTPS 解密代理 (mitmproxy)
└── deploy/             # 部署脚本
```
