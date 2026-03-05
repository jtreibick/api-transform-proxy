# API Transform Proxy (Cloudflare Worker)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jtreibick/api-transform-proxy)

Customer-self-hosted Worker that relays upstream API calls and optionally applies a JSONata transform.

## Required setup

- `CONFIG` KV binding must exist and be bound in `wrangler.toml`.
- `jsonata` must be installed from `package.json` dependencies.

`wrangler.toml` should include:

```toml
[[kv_namespaces]]
binding = "CONFIG"
```

## Endpoints

- `GET /`
  - Status page only.
  - Never creates or rotates keys.
  - Shows initialized state and next step.
- `GET /init`
  - Creates `proxy_key` once if not initialized.
  - Shows the generated key exactly once.
  - If already initialized, does not reveal key.
- `POST /invoke`
  - Requires header `X-Proxy-Key`.
  - Requires `Content-Type: application/json`.
  - Relays request to upstream and returns envelope:
    - success: `{ "ok": true, "data": ..., "meta": { ... } }`
    - error: `{ "ok": false, "error": { "code": ..., "message": ... }, "meta": { ... } }`
- `POST /rotate`
  - Requires current `X-Proxy-Key`.
  - Rotates key and returns new key once.

## /invoke request shape

```json
{
  "upstream": {
    "method": "GET",
    "url": "https://api.example.com/resource",
    "headers": { "Authorization": "Bearer ..." },
    "body": { "type": "none" }
  },
  "transform": {
    "expr": "body.items.{\"id\": id}",
    "when": {
      "status": { "allow": ["2xx"] },
      "content_type": { "allow": ["application/json", "application/*+json"] },
      "max_response_bytes": 500000
    }
  }
}
```

## Important behavior

- `/invoke` returns structured validation errors for malformed payloads (`INVALID_REQUEST`) with:
  - `details.expected`
  - `details.problems[]`
  - `details.received` snippet
- Transform errors are explicit:
  - `NON_JSON_RESPONSE` (422) when transform requested but upstream is not JSON.
  - `TRANSFORM_ERROR` (422) when JSONata evaluation fails.
- Startup/runtime hard failures are wrapped by top-level error handling to avoid opaque Worker crashes.
