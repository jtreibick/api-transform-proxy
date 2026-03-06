#!/usr/bin/env bash
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

# Writes a fresh 32-byte base64 AES key into Cloudflare Worker secret store.
# If you need to preserve existing key material, do not re-run this command.
openssl rand -base64 32 | npx wrangler secret put MASTER_ENCRYPTION_KEY

echo "MASTER_ENCRYPTION_KEY set via Wrangler secret."
