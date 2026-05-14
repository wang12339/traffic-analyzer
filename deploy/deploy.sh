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
API_PORT=${API_PORT:-8080}
FRONTEND_PORT=${FRONTEND_PORT:-3001}
API_KEY=${API_KEY:-traffic-admin-$(uuidgen 2>/dev/null || echo "changeme")}
DB_NAME=${DB_NAME:-traffic}
ROUTER_IP=${ROUTER_IP:-192.168.66.1}
ROUTER_PASS=${ROUTER_PASS:-admin}

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
pkill -f "target/debug/ingest" 2>/dev/null || true
sleep 1
API_KEY="$API_KEY" RUST_LOG=info nohup "$PROJECT/target/debug/ingest" \
    --listen "0.0.0.0:$INGEST_PORT" \
    --clickhouse "localhost:$CLICKHOUSE_PORT" \
    --db-name "$DB_NAME" > /tmp/ingest.log 2>&1 &
echo "   Ingest: PID $! (TCP :$INGEST_PORT + UDP :$UDP_PORT)"

# API
pkill -f "target/debug/api" 2>/dev/null || true
sleep 1
API_KEY="$API_KEY" RUST_LOG=info nohup "$PROJECT/target/debug/api" \
    --listen "0.0.0.0:$API_PORT" \
    --clickhouse "localhost:$CLICKHOUSE_PORT" \
    --db-name "$DB_NAME" > /tmp/api.log 2>&1 &
echo "   API: PID $! (:8080)"

# Frontend
cd "$PROJECT/frontend"
pkill -f "vite.*3001" 2>/dev/null || true
sleep 1
nohup npm run dev > /tmp/frontend.log 2>&1 &
echo "   Frontend: PID $! (:3001)"

echo ""
echo "4/4 部署路由器 agent..."
sshpass -p "$ROUTER_PASS" ssh -o StrictHostKeyChecking=no "root@$ROUTER_IP" "
    killall agent 2>/dev/null || true
    sleep 1
    nohup /root/agent -n br-lan -s 192.168.66.186:$INGEST_PORT > /tmp/agent.log 2>&1 &
" 2>/dev/null && echo "   Router agent: ✅" || echo "   Router agent: ⚠️ 跳过（请手动部署）"

echo ""
echo "═══════════════════════════════════════"
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