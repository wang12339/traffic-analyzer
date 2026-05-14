#!/bin/bash
# Deploy and start the traffic analysis system
set -e

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

echo "=== Traffic Analysis System Setup ==="

# 1. Start ClickHouse
echo "[1/5] Starting ClickHouse..."
if ! pgrep -x clickhouse >/dev/null; then
    clickhouse server --daemon 2>/dev/null || true
    sleep 3
fi
echo "  ClickHouse: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'waiting...')"

# 2. Create ClickHouse schema
echo "[2/5] Creating schema..."
clickhouse client -q "CREATE DATABASE IF NOT EXISTS traffic" 2>/dev/null || true

# 3. Start ingest server
echo "[3/5] Starting ingest server..."
pkill ingest 2>/dev/null || true
sleep 1
RUST_LOG=info nohup "$PROJECT/target/debug/ingest" > /tmp/ingest.log 2>&1 &
INGEST_PID=$!
echo "  Ingest PID: $INGEST_PID"
sleep 2

# 4. Start API server
echo "[4/5] Starting API server..."
pkill api 2>/dev/null || true
sleep 1
RUST_LOG=info nohup "$PROJECT/target/debug/api" > /tmp/api.log 2>&1 &
API_PID=$!
echo "  API PID: $API_PID"
sleep 1

# 5. Build and start frontend
echo "[5/5] Starting frontend..."
cd "$PROJECT/frontend"
if [ -d "node_modules" ]; then
    nohup npm run dev > /tmp/frontend.log 2>&1 &
    echo "  Frontend: http://localhost:3000"
else
    echo "  Frontend: npm install first (npm install && npm run dev)"
fi

echo ""
echo "=== System Status ==="
echo "  ClickHouse:    http://localhost:8123"
echo "  Ingest Server: :9100 (agent TCP)"
echo "  API Server:    http://localhost:8080"
echo "  Frontend:      http://localhost:3000"
echo ""
echo "  To start the router agent:"
echo "    scp target/debug/agent root@192.168.66.1:/root/"
echo "    ssh root@192.168.66.1 './agent --interface br-lan --ingest 192.168.66.186:9100'"
