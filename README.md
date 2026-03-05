# API Transform Proxy (Cloudflare Worker)




Customer-self-hosted Worker that relays upstream API calls and optionally applies a JSONata transform.


## Bootstrap (Step-by-step)

1. Deploy the Worker from Cloudflare:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jtreibick/api-transform-proxy)

2. Open the Worker status page in your browser:
- `https://your-worker.workers.dev/_apiproxy`
- `https://your-worker.workers.dev/` redirects to `/_apiproxy/` (unless `X-Proxy-Key` is sent).

3. Bootstrap keys in your browser (first run only):
- `https://your-worker.workers.dev/_apiproxy/init`
- Trailing slashes are accepted on routes (for example `/_apiproxy/init/`).

- If keys do not exist, the init page shows both:
  - `X-Admin-Key`
  - `X-Proxy-Key`
- Copy and store both immediately. They are shown only when created.

4. Configure your API client:
- Use `X-Admin-Key` for admin endpoints under `/_apiproxy/admin/*`.
- Use `X-Proxy-Key` for runtime requests to `/_apiproxy/request`.

5. Configure behavior:
- Save YAML config through `PUT /_apiproxy/admin/config`.
- Manage enriched upstream headers through `/_apiproxy/admin/headers`.

6. Send proxied requests:
- Call `POST /_apiproxy/request` from Bubble/API client with `X-Proxy-Key`.

7. Rotate keys when needed:
- Proxy key: `POST /_apiproxy/admin/rotate`
- Admin key: `POST /_apiproxy/admin/rotate-admin`

For curl-based API verification, use the **Testing out your proxy** section below.

## Key management

- Keys are shown only once on `GET /_apiproxy/init` when they are created.
- If keys already exist, `GET /_apiproxy/init` will not reveal them again.

Proxy key rotation:
- Call `POST /_apiproxy/admin/rotate` with `X-Admin-Key`.
- The endpoint returns the new proxy key once.
- Old proxy key remains valid for a short overlap window (configurable by `ROTATE_OVERLAP_MS`).

Admin key rotation:
- Call `POST /_apiproxy/admin/rotate-admin` with current `X-Admin-Key`.
- The endpoint returns the new admin key once.

Recovery when admin key is lost:
1. Open Cloudflare dashboard for this Worker.
2. Open KV namespace `CONFIG`.
3. Delete `admin_key` (and optionally `proxy_key`, `proxy_key_old`, `proxy_key_old_expires_at`).
4. Revisit `/_apiproxy/init` to recreate missing keys.

## Contract Freeze (Step 1)

### Error response shape (all endpoints)

```json
{
  "error": {
    "code": "UPPER_SNAKE_CASE",
    "message": "Human-readable summary",
    "details": {}
  }
}
```

Notes:
- `error.code` and `error.message` are always present.
- `error.details` is optional.
- Some endpoints may include optional top-level `meta`.

### Root config schema (v1 draft)

```yaml
targetHost: api.vendor.com # string or null

transform:
  enabled: true
  defaultExpr: ""
  fallback: passthrough # passthrough | error | transform_default
  rules:
    - name: errors_json
      status: [4xx, 5xx, 422] # mix classes + exact codes
      type: json              # json | text | binary | any
      headerMatch:
        x-api-mode: legacy    # optional
      expr: |
        { "ok": false, "status": status, "error": body }

header_forwarding:
  mode: blacklist            # blacklist | whitelist
  names:
    - connection
    - host
    - content-length
    - x-proxy-key
    - x-admin-key
    - x-proxy-host
    - xproxyhost
```



## Required setup

- `CONFIG` KV binding must exist and be bound in `wrangler.toml`.
- `jsonata` and `yaml` must be installed from `package.json` dependencies.
- Optional: set Worker variable `BUILD_VERSION` (for `GET /_apiproxy/admin/version`), e.g. a git SHA or release tag.
- Optional: set `ALLOWED_HOSTS` as comma-separated hosts. Admin-managed hosts are stored in KV and merged with this list.
- Optional: set `ROTATE_OVERLAP_MS` (default `600000`) to keep old proxy key valid briefly after rotation.

`wrangler.toml` should include:

```toml
[[kv_namespaces]]
binding = "CONFIG"
```



## Endpoints

- `GET /_apiproxy`
  - Status page only.
  - Never creates or rotates keys.
  - Shows initialized state and next step.
- `GET /`
  - If `X-Proxy-Key` is absent: redirects (`302`) to `/_apiproxy/`.
  - If `X-Proxy-Key` is present: executes a proxied `GET` to upstream root path (`/`) using the same host resolution, allowlist, header forwarding, and transform pipeline as `POST /_apiproxy/request`.
- `GET /_apiproxy/admin/version`
  - Returns the deployed build version as JSON.
  - Requires header `X-Admin-Key`.
  - Uses `BUILD_VERSION` env var, defaults to `dev` if unset.
- `GET /_apiproxy/init`
  - Bootstraps missing keys:
    - `proxy_key` for `X-Proxy-Key`
    - `admin_key` for `X-Admin-Key`
  - Shows each key once at creation time.
  - If both already exist, keys are not shown.
- `POST /_apiproxy/request`
  - Requires header `X-Proxy-Key`.
  - Requires `Content-Type: application/json`.
  - Host resolution is config-driven:
    - if `targetHost` is set in admin config, it is always used and `X-Proxy-Host` is rejected (`HOST_OVERRIDE_NOT_ALLOWED`).
    - if `targetHost` is unset, `X-Proxy-Host` (or `XProxyHost`) is required (`MISSING_UPSTREAM_HOST`).
  - When host is provided by config/header, `upstream.url` may be relative (for example `/v1/customers`).
  - Forwarding behavior is config-driven by `header_forwarding.mode` + `header_forwarding.names`.
  - Enriched headers are injected last and override both forwarded incoming headers and per-request `upstream.headers`.
  - Relays request to upstream and returns envelope:
    - success: `{ "ok": true, "data": ..., "meta": { ... } }`
    - error: `{ "error": { "code": ..., "message": ..., "details?": ... }, "meta?": { ... } }`
- `POST /_apiproxy/admin/rotate`
  - Requires header `X-Admin-Key`.
  - Rotates key and returns new key once.
  - During overlap window, old key is accepted temporarily (`proxy_key_old` + expiry in KV).
- `POST /_apiproxy/admin/rotate-admin`
  - Requires header `X-Admin-Key`.
  - Rotates admin key and returns the new admin key once.
- `GET /_apiproxy/admin/hosts`
  - Requires header `X-Admin-Key`.
  - Returns `managed_hosts`, `env_hosts`, and merged `effective_hosts`.
- `POST /_apiproxy/admin/hosts`
  - Requires header `X-Admin-Key`.
  - Body: `{ "host": "api.vendor.com" }` or `{ "host": "https://api.vendor.com" }`
  - Adds host to KV-managed allowlist.
- `DELETE /_apiproxy/admin/hosts?host=api.vendor.com`
  - Requires header `X-Admin-Key`.
  - Removes host from KV-managed allowlist.
- `GET /_apiproxy/admin/config`
  - Requires header `X-Admin-Key`.
  - Returns current config YAML (`text/yaml`).
- `PUT /_apiproxy/admin/config`
  - Requires header `X-Admin-Key`.
  - Accepts config YAML in request body.
  - Validates and persists normalized config to KV.
- `POST /_apiproxy/admin/config/validate`
  - Requires header `X-Admin-Key`.
  - Accepts config YAML body.
  - Returns normalized config without saving.
- `POST /_apiproxy/admin/config/test-rule`
  - Requires header `X-Admin-Key`.
  - Accepts JSON with optional `config_yaml` or `config`, plus required sample `response`.
  - Returns matched rule, expression source, fallback behavior, transform output, and rule-match trace.
- `GET /_apiproxy/admin/headers`
  - Requires header `X-Admin-Key`.
  - Returns enriched header names only (never values): `{ "enriched_headers": ["authorization", "..."] }`.
- `PUT /_apiproxy/admin/headers/:name`
  - Requires header `X-Admin-Key`.
  - Requires `Content-Type: application/json` with body `{ "value": "..." }`.
  - Creates/updates one enriched upstream header value.
  - Response includes updated `{ "enriched_headers": [...] }`.
- `DELETE /_apiproxy/admin/headers/:name`
  - Requires header `X-Admin-Key`.
  - Deletes one enriched upstream header.
  - Response includes updated `{ "enriched_headers": [...] }`.

Header precedence in runtime requests:
1. Forwarded incoming headers (based on `header_forwarding` policy)
2. `upstream.headers` from request body (overrides forwarded)
3. Enriched headers from admin storage (override all)

## /request body shape

```json
{
  "upstream": {
    "method": "GET",
    "url": "/resource",
    "headers": { "Authorization": "Bearer ..." },
    "body": { "type": "none" }
  }
}
```

`/request` transforms are now selected from admin config (`/_apiproxy/admin/config`) rather than request-body transform expressions.

Example with `X-Proxy-Host`:

```bash
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  -H "X-Proxy-Host: https://api.example.com" \
  --data '{"upstream":{"method":"GET","url":"/v1/customers"}}'
```

## Important behavior

- `/request` returns structured validation errors for malformed payloads (`INVALID_REQUEST`) with:
  - `details.expected`
  - `details.problems[]`
  - `details.received` snippet
- Transform errors are explicit:
  - `NON_JSON_RESPONSE` (422) when selected transform runs against invalid/unparseable JSON.
  - `TRANSFORM_ERROR` (422) when JSONata evaluation fails.
- Startup/runtime hard failures are wrapped by top-level error handling to avoid opaque Worker crashes.
- Key rotation uses a dual-key overlap window to avoid immediate client lockout during key propagation.

## Migration notes

- Request-body `transform` expressions are no longer the primary runtime transform path.
- Runtime transform behavior is now selected from admin YAML config at `/_apiproxy/admin/config`.
- Existing request payloads with `upstream` continue to work.
- `X-Proxy-Host` behavior is controlled by `targetHost`:
  - `targetHost` set: header is rejected (`HOST_OVERRIDE_NOT_ALLOWED`).
  - `targetHost` unset/null: header is required (`MISSING_UPSTREAM_HOST`).

## Testing out your proxy

Quick request test:

```bash
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  -H "X-Proxy-Host: https://httpbin.org" \
  --data '{"upstream":{"method":"GET","url":"/json"}}'
```

Full smoke test sequence:

Set variables:

```bash
export WORKER_URL="https://your-worker.workers.dev"
```

Bootstrap keys first (shown once when created):

```bash
curl -sS "$WORKER_URL/_apiproxy/init"
```

Then set:

```bash
export ADMIN_KEY="value-shown-by-init"
export PROXY_KEY="value-shown-by-init"
```

1) Validate config YAML (no persistence):

```bash
curl -sS -X POST "$WORKER_URL/_apiproxy/admin/config/validate" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: text/yaml" \
  --data-binary @examples/config-basic.yaml
```

2) Save config YAML:

```bash
curl -sS -X PUT "$WORKER_URL/_apiproxy/admin/config" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: text/yaml" \
  --data-binary @examples/config-basic.yaml
```

3) Test transform rule matcher:

```bash
curl -sS -X POST "$WORKER_URL/_apiproxy/admin/config/test-rule" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data @examples/test-rule-4xx.json
```

4) Set/list/delete enriched headers:

```bash
curl -sS -X PUT "$WORKER_URL/_apiproxy/admin/headers/authorization" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data '{"value":"Bearer SECRET_TOKEN"}'

curl -sS "$WORKER_URL/_apiproxy/admin/headers" \
  -H "X-Admin-Key: $ADMIN_KEY"

curl -sS -X DELETE "$WORKER_URL/_apiproxy/admin/headers/authorization" \
  -H "X-Admin-Key: $ADMIN_KEY"
```

5) Run request path:

```bash
curl -sS "$WORKER_URL/_apiproxy/request" \
  -H "Content-Type: application/json" \
  -H "X-Proxy-Key: $PROXY_KEY" \
  -H "X-Proxy-Host: https://httpbin.org" \
  --data '{"upstream":{"method":"GET","url":"/json"}}'
```

## Acceptance checklist

- `GET /_apiproxy` never creates keys.
- `GET /_apiproxy/init` creates missing proxy/admin keys once; subsequent calls do not reveal existing keys.
- `/request` rejects missing proxy auth key with consistent error shape.
- Host resolution follows config:
  - `targetHost` set => rejects `X-Proxy-Host`.
  - `targetHost` unset => requires `X-Proxy-Host`.
- `PUT /_apiproxy/admin/config` rejects unknown fields (`INVALID_CONFIG`).
- `POST /_apiproxy/admin/config/test-rule` returns deterministic `trace`.
- `GET /_apiproxy/admin/headers` returns names only, never secret values.
- `header_forwarding` policy is applied and enriched headers override downstream.
