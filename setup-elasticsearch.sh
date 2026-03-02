#!/usr/bin/env bash
set -euo pipefail

ES_URL="https://${ES_HOST}:${ES_PORT}"
SCRIPT_DIR="$(cd "$(dirname "$0")/ops" && pwd)"

AUTH=()
read -rp "Elasticsearch username (leave empty to skip auth): " ES_USER
if [[ -n "$ES_USER" ]]; then
  read -rsp "Elasticsearch password: " ES_PASS
  echo
  AUTH=(-u "${ES_USER}:${ES_PASS}")
fi

echo "==> Creating ILM policy..."
curl -sSk -X PUT "${ES_URL}/_ilm/policy/mongo-logs-ilm-policy" \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d @"${SCRIPT_DIR}/elasticsearch-ilm-policy.json"
echo

echo "==> Creating index template..."
curl -sSk -X PUT "${ES_URL}/_index_template/mongo-logs-template" \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d @"${SCRIPT_DIR}/elasticsearch-template.json"
echo

echo "==> Creating initial index with write alias..."
curl -sSk -X PUT "${ES_URL}/mongo-logs-proxy-000001" \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "aliases": {
      "mongo-logs": { "is_write_index": true }
    }
  }'
echo

echo "==> Done. Fluent Bit should write to ES_INDEX=mongo-logs"
