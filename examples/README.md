# Example requests

Set variables:

```bash
export WORKER_URL="https://your-worker.workers.dev"
export PROXY_KEY="replace-with-your-key"
export ADMIN_KEY="replace-with-admin-key"
```

## 1) GET passthrough

```bash
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/get-passthrough.json
```

## 2) JSONata transform

```bash
# Transform behavior is now config-driven. First set config YAML via admin endpoint:
curl -sS -X PUT "$WORKER_URL/_apiproxy/admin/config" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: text/yaml" \
  --data-binary @examples/config-basic.yaml

# Then execute a normal request; transform rule selection happens in runtime from config.
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/jsonata-transform.json
```

## 3) Gated transform (only 4xx/5xx)

```bash
# Use config test-rule endpoint to validate matcher behavior before runtime:
curl -sS -X POST "$WORKER_URL/_apiproxy/admin/config/test-rule" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data @examples/test-rule-4xx.json

# Then run a normal request path.
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/gated-transform-errors-only.json
```

## 4) URL-encoded forwarding

```bash
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/urlencoded-forwarding.json
```

## 5) Enriched headers admin CRUD

```bash
# Set one enriched header value (never returned by list endpoint):
curl -sS -X PUT "$WORKER_URL/_apiproxy/admin/headers/authorization" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data '{"value":"Bearer SECRET_TOKEN"}'

# List header names only:
curl -sS "$WORKER_URL/_apiproxy/admin/headers" \
  -H "X-Admin-Key: $ADMIN_KEY"

# Delete header:
curl -sS -X DELETE "$WORKER_URL/_apiproxy/admin/headers/authorization" \
  -H "X-Admin-Key: $ADMIN_KEY"
```
