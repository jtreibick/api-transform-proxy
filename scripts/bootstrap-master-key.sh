#!/usr/bin/env bash
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

# Idempotent by default:
# - If MASTER_ENCRYPTION_KEY already exists, script does nothing.
# - Pass --force to overwrite and rotate the key.
FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

if [[ "$FORCE" -ne 1 ]]; then
  if npm exec wrangler secret list -- --json 2>/dev/null | tr -d '[:space:]' | grep -q '"name":"MASTER_ENCRYPTION_KEY"'; then
    echo "MASTER_ENCRYPTION_KEY already exists. Skipping."
    exit 0
  fi
fi

echo "Setting MASTER_ENCRYPTION_KEY..."
openssl rand -base64 32 | npm exec wrangler secret put MASTER_ENCRYPTION_KEY

echo "MASTER_ENCRYPTION_KEY set via Wrangler secret."
