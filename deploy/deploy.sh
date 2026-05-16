#!/bin/bash
# 流量分析系统 - 一键部署脚本
set -e

cd "$(dirname "$0")/.."
PROJECT="$PWD"
echo "═══════════════════════════════════════"
echo "  流量分析系统 v1.0 - 部署"
echo "═══════════════════════════════════════"

# ─── 配置 ───
CLICKHOUSE_PORT=${CLICKHOUSE_PORT:-8123}
INGEST_PORT=${INGEST_PORT:-9100}
UDP_PORT=${UDP_PORT:-2055}
API_PORT=${API_PORT:-8970}
FRONTEND_PORT=${FRONTEND_PORT:-3001}
API_KEY=${API_KEY:-traffic-admin-$(uuidgen 2>/dev/null || echo "changeme")}
DB_NAME=${DB_NAME:-traffic}
ROUTER_IP=${ROUTER_IP:-}
ROUTER_PASS=${ROUTER_PASS:-}
# 自动检测本机 IP
MY_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
INGEST_IP=${INGEST_IP:-${MY_IP:-127.0.0.1}}

echo ""
echo "1/4 启动 ClickHouse..."
if ! pgrep -x clickhouse >/dev/null; then
    clickhouse server --daemon 2>/dev/null || true
    sleep 2
fi
echo "   ClickHouse: $(curl -s http://localhost:$CLICKHOUSE_PORT/ping)"

echo ""
echo "2/4 初始化数据库..."
clickhouse client --database="$DB_NAME" -q "CREATE DATABASE IF NOT EXISTS $DB_NAME" 2>/dev/null || true
# 表已由 ingest 自动创建

echo ""
echo "3/4 启动服务..."
# Ingest
pkill -f "target/release/ingest" 2>/dev/null || true
sleep 1
API_KEY="$API_KEY" RUST_LOG=info nohup "$PROJECT/target/release/ingest" \
    --listen "0.0.0.0:$INGEST_PORT" \
    --clickhouse "localhost:$CLICKHOUSE_PORT" \
    --db-name "$DB_NAME" > /tmp/ingest.log 2>&1 &
echo "   Ingest: PID $! (TCP :$INGEST_PORT + UDP :$UDP_PORT)"

# API
pkill -f "target/release/api" 2>/dev/null || true
sleep 1
API_KEY="$API_KEY" RUST_LOG=info nohup "$PROJECT/target/release/api" \
    --listen "0.0.0.0:$API_PORT" \
    --clickhouse "localhost:$CLICKHOUSE_PORT" \
    --db-name "$DB_NAME" > /tmp/api.log 2>&1 &
echo "   API: PID $! (:8970)"

# Frontend
cd "$PROJECT/frontend"
pkill -f "vite.*3001" 2>/dev/null || true
sleep 1
nohup npm run dev > /tmp/frontend.log 2>&1 &
echo "   Frontend: PID $! (:3001)"

echo ""
echo "4/4 部署路由器 agent..."
if [ -z "$ROUTER_IP" ] || [ -z "$ROUTER_PASS" ]; then
    echo "   Router agent: ⚠️ 跳过（设置 ROUTER_IP 和 ROUTER_PASS 环境变量以启用）"
else
    SSHPASS="$ROUTER_PASS" sshpass -e ssh -o StrictHostKeyChecking=no "root@$ROUTER_IP" "
        killall agent 2>/dev/null || true
        sleep 1
        nohup /root/agent -n br-lan -s ${INGEST_IP}:${INGEST_PORT} > /tmp/agent.log 2>&1 &
    " 2>/dev/null && echo "   Router agent: ✅" || echo "   Router agent: ⚠️ 跳过（请手动部署）"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  构建 release 二进制..."
cargo build --release -p ingest -p api 2>&1 | tail -3
echo ""
echo "  部署完成！"
echo ""
echo "  前端:     http://localhost:$FRONTEND_PORT"
echo "  API:      http://localhost:$API_PORT"
echo "  API Key:  $API_KEY"
echo "  Ingest:   TCP :$INGEST_PORT / UDP :$UDP_PORT"
echo "  ClickHouse: localhost:$CLICKHOUSE_PORT"
echo ""
echo "  API 调用示例:"
echo '    curl -H "X-API-Key: $API_KEY" http://localhost:$API_PORT/api/stats'
echo ""
echo "  路由器 agent 日志: ssh root@$ROUTER_IP 'cat /tmp/agent.log'"
echo "═══════════════════════════════════════"