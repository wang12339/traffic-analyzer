# 流量分析系统 · Traffic Analyzer

[![CI](https://github.com/wang12339/traffic-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/wang12339/traffic-analyzer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-edition?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](https://react.dev/)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-24.3-FFCC01?logo=clickhouse&logoColor=white)](https://clickhouse.com/)

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

- Rust 2021 edition (Rust >= 1.80)
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

### Docker Compose 部署

```bash
docker compose up -d
# API: localhost:8970, 前端: localhost:3001
```

### 一键部署（本地）

```bash
./deploy/deploy.sh
```

或使用桌面快捷方式（macOS）：双击 `流量分析系统.command` 开关系统。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `API_KEY` | `""` (无认证) | 设置后所有 API 请求需携带 `X-API-Key` 头部 |
| `ALLOWED_ORIGINS` | `*` (全部允许) | 逗号分隔的 CORS 允许源 |
| `ROUTER_SSH_HOST` | `""` (禁用) | 设置后启用 `/api/agent/*` 远程管理 |
| `ROUTER_SSH_PASSWORD` | `admin` | 路由器 SSH 密码 |
| `ROUTER_SSH_PORT` | `22` | 路由器 SSH 端口 |
| `INGEST_ADDR` | `192.168.66.186:9100` | Agent 管理的 ingest 地址 |

### 启动时设置 API Key

```bash
API_KEY=my-secret-key RUST_LOG=info ./target/release/api
```

## API 示例

```bash
# 设置 API Key（可选）
API_KEY=my-secret-key
AUTH=""
# 如果启用了 API Key：
# AUTH="-H X-API-Key:$API_KEY"

# 概览统计
curl $AUTH http://localhost:8970/api/stats

# 实时流量
curl $AUTH http://localhost:8970/api/live

# 设备洞察
curl $AUTH http://localhost:8970/api/insights

# 微信分析
curl $AUTH http://localhost:8970/api/analysis/wechat

# CSV 导出
curl $AUTH "http://localhost:8970/api/export/csv?since=1h"
```

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
│       ├── storage.rs      # ClickHouse 存储层
│       ├── tcp_reasm.rs    # TCP 重组 & TLS 会话
│       ├── tls_parser.rs   # TLS Client/Server Hello 解析
│       ├── http_parser.rs  # HTTP 请求解析
│       ├── dns_parser.rs   # DNS 查询解析
│       ├── mysql_parser.rs # MySQL 协议解析
│       ├── redis_parser.rs # Redis RESP 协议解析
│       └── quic_parser.rs  # QUIC Initial 包解析
├── api/                # REST API 服务 (Actix-web)
│   └── src/routes/
│       ├── queries.rs      # 数据查询
│       ├── analysis.rs     # 分析 & 洞见
│       └── agent.rs        # Agent 远程管理
├── traffic-core/       # 共享类型 & 多引擎分类器
│   └── src/
│       └── classifier.rs  # 130+ 条应用识别规则
├── frontend/           # React 19 + TypeScript + Ant Design
│   └── src/components/
│       ├── DashboardPage.tsx
│       ├── InsightsBoard.tsx
│       ├── TopologyView.tsx
│       ├── AlertsView.tsx
│       ├── WeChatAnalysis.tsx
│       │   └── ...
├── deploy/             # 部署脚本 & Dockerfile
│   ├── deploy.sh
│   ├── docker-compose.yml
│   ├── Dockerfile.api
│   └── Dockerfile.ingest
├── mitm_agent.py       # HTTPS 解密代理 (mitmproxy)
└── .dockerignore
```
