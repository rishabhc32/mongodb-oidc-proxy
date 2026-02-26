#!/usr/bin/env bash
set -euo pipefail

ES_URL="http://${ES_HOST}:${ES_PORT}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Creating ILM policy..."
curl -s -X PUT "${ES_URL}/_ilm/policy/mongo-logs-ilm-policy" \
  -H "Content-Type: application/json" \
  -d @"${SCRIPT_DIR}/elasticsearch-ilm-policy.json"
echo

echo "==> Creating index template..."
curl -s -X PUT "${ES_URL}/_index_template/mongo-logs-template" \
  -H "Content-Type: application/json" \
  -d @"${SCRIPT_DIR}/elasticsearch-template.json"
echo

echo "==> Creating initial index with write alias..."
curl -s -X PUT "${ES_URL}/mongo-logs-proxy-000001" \
  -H "Content-Type: application/json" \
  -d '{
    "aliases": {
      "mongo-logs": { "is_write_index": true }
    }
  }'
echo

echo "==> Done. Fluent Bit should write to ES_INDEX=mongo-logs"
