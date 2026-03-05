# Example requests

Set variables:

```bash
export WORKER_URL="https://your-worker.workers.dev"
export PROXY_KEY="replace-with-your-key"
```

## 1) GET passthrough

```bash
curl -sS "$WORKER_URL/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/get-passthrough.json
```

## 2) JSONata transform

```bash
curl -sS "$WORKER_URL/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/jsonata-transform.json
```

## 3) Gated transform (only 4xx/5xx)

```bash
curl -sS "$WORKER_URL/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/gated-transform-errors-only.json
```

## 4) URL-encoded forwarding

```bash
curl -sS "$WORKER_URL/invoke" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  --data @examples/urlencoded-forwarding.json
```
