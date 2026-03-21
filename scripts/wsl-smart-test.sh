#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://localhost"
TOKEN="${TOKEN:-}"

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: missing TOKEN env var"
  exit 1
fi

echo "TOKEN_OK length=${#TOKEN}"

USERS_JSON=$(curl -ks "${BASE_URL}/api/users/search?isSubscriber=true&isActive=true&page=1&limit=50" -H "Authorization: Bearer ${TOKEN}")
SUBSCRIBER_ID=$(printf '%s' "$USERS_JSON" | python3 -c 'import sys, json; data=json.load(sys.stdin); rows=data.get("data", []); print(rows[0]["id"] if rows else "")')

if [[ -z "$SUBSCRIBER_ID" ]]; then
  echo "USERS_JSON=$USERS_JSON"
  echo "ERROR: no subscriber id"
  exit 1
fi

echo "SUBSCRIBER_ID=${SUBSCRIBER_ID}"

TEST_JSON=$(curl -ks -X POST "${BASE_URL}/api/smart-notifications/weekly/test/${SUBSCRIBER_ID}" -H "Authorization: Bearer ${TOKEN}")

echo "TEST_JSON=$TEST_JSON"
