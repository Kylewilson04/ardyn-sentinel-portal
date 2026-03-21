#!/bin/bash
# Phase 3 Reduced Webapp Deploy Script
# Run on VM: bash /home/ardyn/ardyn-sentinel-portal/deploy_phase3.sh
set -e

echo "=== Phase 3 Reduced Webapp Deploy ==="
date

GIT_DIR="/home/ardyn/ardyn-sentinel-portal"
cd "$GIT_DIR"

echo "[1/5] Git pull..."
git pull origin master

echo "[2/5] Restart webapp service..."
sudo systemctl restart ads-webapp || systemctl --user restart ads-webapp

echo "[3/5] Verify webapp is running..."
sleep 3
curl -s http://localhost:8080/health | python3 -m json.tool 2>/dev/null || echo "health check failed"

echo "[4/5] Verify gateway is reachable from webapp..."
curl -s http://localhost:8443/health | python3 -m json.tool 2>/dev/null || echo "gateway unreachable"

echo "[5/5] Test route availability..."
for route in /billing /audit /health /v1/verify/test-job-id /ledger /ledger_api; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080$route")
    echo "  $route -> $code"
done

echo ""
echo "=== Deploy complete ==="
