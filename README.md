# API Transform Proxy (Cloudflare Worker)




Customer-self-hosted Worker that relays upstream API calls and optionally applies a JSONata transform.


## Bootstrap (Step-by-step)

1. Deploy the Worker from Cloudflare:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jtreibick/api-transform-proxy)

2. Set optional bootstrap config YAML (recommended):
- In Cloudflare dashboard: Worker -> Settings -> Variables -> add `BOOTSTRAP_CONFIG_YAML` (text), then paste your YAML config.
- Or in Wrangler, set `BOOTSTRAP_CONFIG_YAML` under `[vars]` before deploy (example in **Required setup** below).
- If this variable is set, it overrides stored KV config for runtime behavior.

3. Open the Worker status page in your browser:
- `https://your-worker.workers.dev/_apiproxy`
- `https://your-worker.workers.dev/` redirects to `/_apiproxy/` (unless `X-Proxy-Key` is sent).

4. Bootstrap keys in your browser (first run only):
- `https://your-worker.workers.dev/_apiproxy`
- Trailing slashes are accepted on routes (for example `/_apiproxy/`).

- If keys do not exist, the proxy page shows newly-created keys:
  - `X-Admin-Key`
  - `X-Proxy-Key`
- Copy and store both immediately. They are shown only when created.

5. Configure your API client:
- Use `X-Admin-Key` for admin endpoints under `/_apiproxy/admin/*`.
- Use `X-Proxy-Key` for runtime requests to `/_apiproxy/request`.

6. Configure behavior:
- Save YAML config through `PUT /_apiproxy/admin/config`.
- Manage enriched upstream headers through `/_apiproxy/admin/headers`.
- If `BOOTSTRAP_CONFIG_YAML` is set, it takes precedence over config saved through admin endpoints.
- For deploy-time secret headers, set `BOOTSTRAP_ENRICHED_HEADERS_JSON` + a secret like `TARGET_AUTH_BEARER` (see **Required setup**).

7. Send proxied requests:
- Call `POST /_apiproxy/request` from Bubble/API client with `X-Proxy-Key`.

8. Rotate keys when needed:
- Self-rotation with same credential:
  - Proxy key: `POST /_apiproxy/keys/proxy/rotate` with `X-Proxy-Key`
  - Issuer key: `POST /_apiproxy/keys/issuer/rotate` with `X-Issuer-Key`
  - Admin key: `POST /_apiproxy/keys/admin/rotate` with `X-Admin-Key`
- Admin override rotation:
  - `POST /_apiproxy/admin/keys/{proxy|issuer|admin}/rotate` with `X-Admin-Key`

For curl-based API verification, use the **Testing out your proxy** section below.

## Key management

- Keys are shown only once on `GET /_apiproxy` when they are created.
- If keys already exist, `GET /_apiproxy` will not reveal them again.

Key rotation:
- Proxy self-rotation: `POST /_apiproxy/keys/proxy/rotate` with `X-Proxy-Key`.
- Issuer self-rotation: `POST /_apiproxy/keys/issuer/rotate` with `X-Issuer-Key`.
- Admin self-rotation: `POST /_apiproxy/keys/admin/rotate` with `X-Admin-Key`.
- Admin override: `POST /_apiproxy/admin/keys/{proxy|issuer|admin}/rotate` with `X-Admin-Key`.
- All rotate responses include `expiry_seconds` from YAML `apiKeyPolicy` (`null` means long-lived).

Recovery when admin key is lost:
1. Open Cloudflare dashboard for this Worker.
2. Open KV namespace `CONFIG`.
3. Delete `admin_key` (and optionally `admin_key_old`, `admin_key_old_expires_at`, `proxy_key`, `proxy_key_old`, `proxy_key_old_expires_at`, `issuer_key`, `issuer_key_old`, `issuer_key_old_expires_at`).
4. Revisit `/_apiproxy` to recreate missing keys.

<p><strong style="color:#b91c1c;">Important: after deleting keys in Cloudflare KV, propagation may take up to 2 minutes. During that window, <code>/_apiproxy</code> can still detect the old key state and will not recreate keys yet. Wait and refresh to avoid confusion.</strong></p>

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

debug:
  max_debug_session_seconds: 3600     # default 1 hour, max 604800 (7 days)

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
- Deploy from repository root so Wrangler reads the intended `wrangler.toml`.
- `jsonata` and `yaml` must be installed from `package.json` dependencies.
- Optional: set `BOOTSTRAP_CONFIG_YAML` to define config from env. When set, it overrides KV config.
- Optional: `debug.max_debug_session_seconds` controls debug-window max duration; default `3600`, max `604800`.
- Debug traces always redact: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-proxy-key`, `x-admin-key`.
- Optional: set `BOOTSTRAP_ENRICHED_HEADERS_JSON` to define enriched headers from deploy config.
  - Values support `${VAR_NAME}` placeholders.
  - Example secret variable: `TARGET_AUTH_BEARER` (or `targetAuthBearer`).
  - Env-managed headers are locked from `PUT/DELETE /_apiproxy/admin/headers/:name`; update env + redeploy instead.
- Optional: set Worker variable `BUILD_VERSION` (for `GET /_apiproxy/admin/version`), e.g. a git SHA or release tag.
- Optional: set `ALLOWED_HOSTS` as comma-separated hosts to enforce host allowlisting.
- Optional: set `ROTATE_OVERLAP_MS` (default `600000`) to keep old proxy key valid briefly after rotation.

`wrangler.toml` should include:

```toml
[[kv_namespaces]]
binding = "CONFIG"

# Optional bootstrap config (when set, overrides stored KV config)
[vars]
BOOTSTRAP_CONFIG_YAML = """
targetHost: null
transform:
  enabled: true
  defaultExpr: ""
  fallback: passthrough
  rules: []
header_forwarding:
  mode: blacklist
  names:
    - connection
    - host
    - content-length
    - x-proxy-key
    - x-admin-key
    - x-proxy-host
    - xproxyhost
"""

# Optional deploy-time enriched headers (when set, synced to KV and env-managed)
BOOTSTRAP_ENRICHED_HEADERS_JSON = """
{
  "authorization": "Bearer ${TARGET_AUTH_BEARER}"
}
"""
```

If you want admin API config updates (`PUT /_apiproxy/admin/config`) to take effect, unset `BOOTSTRAP_CONFIG_YAML`.
If you want API header updates (`PUT/DELETE /_apiproxy/admin/headers/:name`) to take effect for env-managed header names, unset `BOOTSTRAP_ENRICHED_HEADERS_JSON`.

Recommended: store `TARGET_AUTH_BEARER` as a Cloudflare Worker Secret (not plain text in `wrangler.toml`).

Example:

```bash
wrangler secret put TARGET_AUTH_BEARER
# then paste secret value when prompted
```

One-command deploy:

```bash
npm run deploy:cf
```

Wrangler-native KV provisioning:
- Keep `[[kv_namespaces]]` with `binding = "CONFIG"` in `wrangler.toml` (no hard-coded id).
- Use Wrangler v4.45+ (`npm exec wrangler deploy`), which provisions missing KV namespace resources during deploy.

## Endpoints

- `GET /_apiproxy`
  - Status + bootstrap page.
  - If keys are missing, creates missing key(s) and shows each newly-created key once.
  - If keys already exist, shows running/status view and never reveals existing key values.
- `GET /`
  - If `X-Proxy-Key` is absent: redirects (`302`) to `/_apiproxy/`.
  - If `X-Proxy-Key` is present: executes a proxied `GET` to upstream root path (`/`) using the same host resolution, allowlist, header forwarding, and transform pipeline as `POST /_apiproxy/request`.
- `GET /_apiproxy/admin/version`
  - Returns the deployed build version as JSON.
  - Requires header `X-Admin-Key`.
  - Uses `BUILD_VERSION` env var, defaults to `dev` if unset.
- `GET /_apiproxy/admin`
  - Browser admin console for all admin endpoints.
  - Prompts for `X-Admin-Key`, exchanges it for short-lived access token, then provides UI controls for Status, Enrichments, Logging, Outbound Auth, Inbound Auth, API Sandbox, and Config.
  - Logging Endpoint URL + Logging Auth Header are read from YAML config (`debug.loggingEndpoint`) and show blank when not set.
- `POST /_apiproxy/admin/access-token`
  - Requires header `X-Admin-Key`.
  - Response: `{ "ok": true, "data": { "access_token": "...", "expires_at_ms": 123, "ttl_seconds": 3600 } }`
- `GET /_apiproxy/admin/debug`
  - Requires `X-Admin-Key`.
  - Returns debug status, remaining TTL, and configured `debug.max_debug_session_seconds`.
- `PUT /_apiproxy/admin/debug`
  - Requires `X-Admin-Key`.
  - Requires `Content-Type: application/json`.
  - Body:
    - enable: `{ "enabled": true, "ttl_seconds": 3600 }`
    - disable: `{ "enabled": false }`
  - `ttl_seconds` must be <= `debug.max_debug_session_seconds` from config.
- `DELETE /_apiproxy/admin/debug`
  - Requires `X-Admin-Key`.
  - Disables debug immediately (no request body required).
- `GET /_apiproxy/admin/debug/last`
  - Requires `X-Admin-Key`.
  - Returns most recent debug trace captured in this Worker instance.
  - `Accept: text/plain` returns plain text trace.
- `PUT /_apiproxy/admin/debug/loggingSecret`
  - Requires `X-Admin-Key`.
  - Requires `Content-Type: application/json`.
  - Stores logging auth secret in KV.
  - Body: `{ "value": "..." }`
- `GET /_apiproxy/admin/debug/loggingSecret`
  - Requires `X-Admin-Key`.
  - Returns whether a logging auth secret is currently set.
- `DELETE /_apiproxy/admin/debug/loggingSecret`
  - Requires `X-Admin-Key`.
  - Removes logging auth secret from KV.
- `POST /_apiproxy/request`
  - Requires header `X-Proxy-Key`.
  - Requires `Content-Type: application/json`.
  - Host resolution is config-driven:
    - if `targetHost` is set in admin config, it is always used and `X-Proxy-Host` is rejected (`HOST_OVERRIDE_NOT_ALLOWED`).
    - if `targetHost` is unset, `X-Proxy-Host` is required (`MISSING_UPSTREAM_HOST`).
  - When host is provided by config/header, `upstream.url` may be relative (for example `/v1/customers`).
  - Forwarding behavior is config-driven by `header_forwarding.mode` + `header_forwarding.names`.
  - Enriched headers are injected last and override both forwarded incoming headers and per-request `upstream.headers`.
  - Debug trace capture runs when both:
    - debug window is active (`PUT /_apiproxy/admin/debug`)
    - request header `X-Proxy-Debug: 1` is present
  - When debug is active, response headers include:
    - `X-Proxy-Debug: True`
    - `X-Proxy-Debug-Trace-Id: ...`
    - `X-Proxy-Debug-Logging-Endpoint-Status: off|ok|error:<CODE>[:HTTP_STATUS]`
  - Relays request to upstream and returns envelope:
    - success: `{ "ok": true, "data": ..., "meta": { ... } }`
    - error: `{ "error": { "code": ..., "message": ..., "details?": ... }, "meta?": { ... } }`
- `POST /_apiproxy/keys/proxy/rotate`
  - Requires header `X-Proxy-Key`.
  - Rotates proxy key and returns new key once.
- `POST /_apiproxy/keys/issuer/rotate`
  - Requires header `X-Issuer-Key`.
  - Rotates issuer key and returns new key once.
- `POST /_apiproxy/keys/admin/rotate`
  - Requires header `X-Admin-Key`.
  - Rotates admin key and returns new key once.
- `POST /_apiproxy/admin/keys/{proxy|issuer|admin}/rotate`
  - Requires header `X-Admin-Key`.
  - Admin override rotation for any key kind.
- `GET /_apiproxy/admin/key-rotation-config`
  - Requires header `X-Admin-Key`.
  - Returns titled key-rotation config fields, including `request_yaml` and API key expiry policy fields.
- `PUT /_apiproxy/admin/key-rotation-config`
  - Requires header `X-Admin-Key`.
  - Requires `Content-Type: application/json`.
  - Saves key-rotation settings where `request_yaml` is a multiline YAML object and all other properties are field-mapped.
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
curl -sS "$WORKER_URL/_apiproxy"
```

Then set:

```bash
export ADMIN_KEY="value-shown-by-bootstrap"
export PROXY_KEY="value-shown-by-bootstrap"
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

- `GET /_apiproxy` creates missing proxy/admin keys once; subsequent calls do not reveal existing keys.
- `/request` rejects missing proxy auth key with consistent error shape.
- Host resolution follows config:
  - `targetHost` set => rejects `X-Proxy-Host`.
  - `targetHost` unset => requires `X-Proxy-Host`.
- `PUT /_apiproxy/admin/config` rejects unknown fields (`INVALID_CONFIG`).
- `POST /_apiproxy/admin/config/test-rule` returns deterministic `trace`.
- `GET /_apiproxy/admin/headers` returns names only, never secret values.
- `header_forwarding` policy is applied and enriched headers override downstream.
