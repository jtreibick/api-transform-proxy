/**
 * API transform relay for Bubble-style clients.
 *
 * Endpoints:
 * - GET /      : status page (never initializes)
 * - GET /init  : one-time key initialization
 * - POST /invoke: authenticated relay + optional JSONata transform
 * - POST /rotate: authenticated key rotation
 */

const KV_PROXY_KEY = "proxy_key";

const DEFAULTS = {
  ALLOWED_HOSTS: "",
  MAX_REQ_BYTES: 256 * 1024,
  MAX_RESP_BYTES: 1024 * 1024,
  MAX_EXPR_BYTES: 16 * 1024,
  TRANSFORM_TIMEOUT_MS: 400,
};

const EXPECTED_INVOKE_SCHEMA = {
  upstream: {
    method: "GET|POST|PUT|PATCH|DELETE",
    url: "https://...",
    headers: "object<string,string> (optional)",
    body: {
      type: "none|json|urlencoded|raw",
      value: "any (optional)",
      raw: "string (optional)",
      content_type: "string (optional)",
    },
  },
  transform: {
    expr: "JSONata expression string",
    when: {
      status: { allow: ["2xx", 400], deny: ["5xx"] },
      content_type: { allow: ["application/json", "application/*+json"], deny: ["text/*"] },
      max_response_bytes: 100000,
    },
  },
};

const SAFE_META_HEADERS = new Set([
  "content-type",
  "cache-control",
  "etag",
  "last-modified",
  "content-language",
  "expires",
]);

let jsonataFactory = null;

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    try {
      if (pathname === "/" && request.method === "GET") {
        return await handleStatusPage(env);
      }
      if (pathname === "/init" && request.method === "GET") {
        return await handleInitPage(env);
      }
      if (pathname === "/invoke" && request.method === "POST") {
        return await handleInvoke(request, env);
      }
      if (pathname === "/rotate" && request.method === "POST") {
        return await handleRotate(request, env);
      }

      return apiError(404, "NOT_FOUND", "Route not found");
    } catch (error) {
      return renderError(error, pathname);
    }
  },
};

class HttpError extends Error {
  constructor(status, code, message, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function renderError(error, pathname) {
  const err = toHttpError(error);

  if ((pathname === "/" || pathname === "/init") && err.status >= 500) {
    return new Response(
      htmlPage(
        "Configuration error",
        `<p><b>Error:</b> ${escapeHtml(err.code)}</p>
         <p>${escapeHtml(err.message)}</p>
         <p>Fix your Worker setup and redeploy.</p>`
      ),
      { status: err.status, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return apiError(err.status, err.code, err.message, err.details);
}

function toHttpError(error) {
  if (error instanceof HttpError) return error;

  return new HttpError(
    500,
    "INTERNAL_ERROR",
    "Unhandled Worker error",
    { cause: String(error?.message || error) }
  );
}

function getEnvInt(env, key, fallback) {
  const v = env[key];
  if (v === undefined || v === null || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function ensureKvBinding(env) {
  if (!env || !env.CONFIG || typeof env.CONFIG.get !== "function" || typeof env.CONFIG.put !== "function") {
    throw new HttpError(
      500,
      "MISSING_KV_BINDING",
      "KV binding CONFIG is missing.",
      {
        setup: "Add [[kv_namespaces]] binding = \"CONFIG\" in wrangler.toml and redeploy.",
      }
    );
  }
}

function getAllowedHosts(env) {
  const raw = (env.ALLOWED_HOSTS ?? DEFAULTS.ALLOWED_HOSTS).trim();
  if (!raw) return null;
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generateSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function loadJsonata() {
  if (jsonataFactory) return jsonataFactory;

  try {
    const mod = await import("jsonata");
    jsonataFactory = mod?.default || mod;
    if (typeof jsonataFactory !== "function") {
      throw new Error("jsonata default export is not a function");
    }
    return jsonataFactory;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_JSONATA_DEPENDENCY",
      "jsonata dependency is not available in this Worker build.",
      {
        setup: "Ensure jsonata is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

async function readJsonWithLimit(request, maxBytes) {
  const reader = request.body?.getReader();
  if (!reader) {
    throw new HttpError(400, "EMPTY_BODY", "Request body is required");
  }

  let total = 0;
  const chunks = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      throw new HttpError(413, "REQUEST_TOO_LARGE", `Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }

  if (total === 0) {
    throw new HttpError(400, "EMPTY_BODY", "Request body is required");
  }

  const text = new TextDecoder().decode(concatUint8Arrays(chunks));
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON");
  }
}

function concatUint8Arrays(chunks) {
  const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function getStoredContentType(headers) {
  return (headers.get("content-type") || "").toLowerCase();
}

function looksJson(contentType) {
  return contentType.includes("application/json") || contentType.includes("+json");
}

function isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function truncateJsonSnippet(value, maxLen = 1200) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen)}...(truncated)`;
}

function enforceInvokeContentType(request) {
  const contentType = getStoredContentType(request.headers);
  if (!contentType.includes("application/json")) {
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
  }
}

function validateInvokePayload(payload) {
  const problems = [];

  if (!isPlainObject(payload)) {
    problems.push("payload must be a JSON object");
    return problems;
  }

  if (!isPlainObject(payload.upstream)) {
    problems.push("payload.upstream is required and must be an object");
    return problems;
  }

  const { upstream } = payload;

  if (typeof upstream.method !== "string") {
    problems.push("upstream.method is required and must be a string");
  } else {
    const m = upstream.method.toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m)) {
      problems.push("upstream.method must be one of GET, POST, PUT, PATCH, DELETE");
    }
  }

  if (typeof upstream.url !== "string" || upstream.url.trim() === "") {
    problems.push("upstream.url is required and must be a non-empty string");
  }

  if (upstream.headers !== undefined && !isPlainObject(upstream.headers)) {
    problems.push("upstream.headers must be an object when provided");
  }

  if (upstream.body !== undefined) {
    if (!isPlainObject(upstream.body)) {
      problems.push("upstream.body must be an object when provided");
    } else {
      const bodyType = String(upstream.body.type || "none").toLowerCase();
      if (!["none", "json", "urlencoded", "raw"].includes(bodyType)) {
        problems.push("upstream.body.type must be one of none, json, urlencoded, raw");
      }
      if (bodyType === "raw" && upstream.body.raw !== undefined && typeof upstream.body.raw !== "string") {
        problems.push("upstream.body.raw must be a string for body.type=raw");
      }
      if (bodyType === "urlencoded") {
        const rawOk = upstream.body.raw === undefined || typeof upstream.body.raw === "string";
        const valOk = upstream.body.value === undefined || isPlainObject(upstream.body.value);
        if (!rawOk || !valOk) {
          problems.push("upstream.body for urlencoded must use raw:string or value:object");
        }
      }
    }
  }

  if (payload.transform !== undefined) {
    if (!isPlainObject(payload.transform)) {
      problems.push("transform must be an object when provided");
    } else {
      if (typeof payload.transform.expr !== "string" || payload.transform.expr.trim() === "") {
        problems.push("transform.expr is required when transform is provided");
      }

      if (payload.transform.when !== undefined && !isPlainObject(payload.transform.when)) {
        problems.push("transform.when must be an object when provided");
      }
    }
  }

  return problems;
}

function assertSafeUpstreamUrl(urlLike, allowedHosts) {
  const u = urlLike instanceof URL ? urlLike : new URL(urlLike);

  if (u.protocol !== "https:") {
    throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "Upstream URL must use https");
  }

  const hostname = u.hostname.toLowerCase();

  if (allowedHosts && !allowedHosts.has(hostname)) {
    throw new HttpError(
      403,
      "UPSTREAM_HOST_NOT_ALLOWED",
      `Upstream host not allowlisted: ${hostname}`,
      { allowed_hosts_hint: "Set ALLOWED_HOSTS env var to allowed domains" }
    );
  }

  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw new HttpError(403, "UPSTREAM_HOST_BLOCKED", "localhost is blocked");
  }

  if (isIpLiteral(hostname)) {
    if (isPrivateOrLinkLocalIp(hostname) || hostname === "169.254.169.254") {
      throw new HttpError(403, "UPSTREAM_IP_BLOCKED", "Private/link-local IPs are blocked");
    }
  }

  return u;
}

function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPrivateOrLinkLocalIp(ip) {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;

  const [a, b] = parts;
  if (a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function matchesStatusList(status, list) {
  for (const item of list) {
    if (typeof item === "number" && status === item) return true;
    if (typeof item !== "string") continue;

    const t = item.trim().toLowerCase();
    if (t === "2xx" && status >= 200 && status < 300) return true;
    if (t === "3xx" && status >= 300 && status < 400) return true;
    if (t === "4xx" && status >= 400 && status < 500) return true;
    if (t === "5xx" && status >= 500 && status < 600) return true;
    if (/^\d+$/.test(t) && status === Number(t)) return true;
  }
  return false;
}

function matchesContentType(contentType, patterns) {
  const ct = String(contentType || "").toLowerCase();
  for (const p of patterns) {
    const pat = String(p || "").toLowerCase();
    if (!pat) continue;
    if (pat === "*") return true;
    if (pat.endsWith("*") && ct.startsWith(pat.slice(0, -1))) return true;
    if (ct.includes(pat)) return true;
  }
  return false;
}

function shouldRunTransform(when, status, contentType, responseBytes) {
  if (!isPlainObject(when)) return true;

  if (isPlainObject(when.status)) {
    if (Array.isArray(when.status.deny) && matchesStatusList(status, when.status.deny)) return false;
    if (Array.isArray(when.status.allow) && !matchesStatusList(status, when.status.allow)) return false;
  }

  if (isPlainObject(when.content_type)) {
    if (Array.isArray(when.content_type.deny) && matchesContentType(contentType, when.content_type.deny)) {
      return false;
    }
    if (Array.isArray(when.content_type.allow) && !matchesContentType(contentType, when.content_type.allow)) {
      return false;
    }
  }

  if (typeof when.max_response_bytes === "number" && responseBytes > when.max_response_bytes) {
    return false;
  }

  return true;
}

async function readResponseWithLimit(resp, maxBytes) {
  const reader = resp.body?.getReader();
  if (!reader) return new Uint8Array();

  let total = 0;
  const chunks = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      throw new HttpError(413, "RESPONSE_TOO_LARGE", `Upstream response exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }

  return concatUint8Arrays(chunks);
}

function decodeBody(buffer) {
  return new TextDecoder().decode(buffer);
}

function parseJsonOrNull(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function toSafeUpstreamHeaders(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) {
    if (SAFE_META_HEADERS.has(k.toLowerCase())) out[k.toLowerCase()] = v;
  }
  return out;
}

async function evalJsonataWithTimeout(exprString, inputObj, timeoutMs) {
  const jsonata = await loadJsonata();
  const expr = jsonata(exprString);

  const task = Promise.resolve(expr.evaluate(inputObj));
  const timeout = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`JSONata timeout after ${timeoutMs}ms`)), timeoutMs);
  });

  return Promise.race([task, timeout]);
}

function successEnvelope(data, meta = {}) {
  return { ok: true, data, meta };
}

function errorEnvelope(code, message, details, meta = {}) {
  const error = { code, message };
  if (details !== undefined && details !== null) error.details = details;
  const out = { ok: false, error };
  if (meta && Object.keys(meta).length > 0) out.meta = meta;
  return out;
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function apiError(status, code, message, details = null, meta = null) {
  return jsonResponse(status, errorEnvelope(code, message, details, meta || {}));
}

async function getProxyKey(env) {
  ensureKvBinding(env);
  return env.CONFIG.get(KV_PROXY_KEY);
}

async function requireProxyKey(request, env) {
  const expected = await getProxyKey(env);
  if (!expected) {
    throw new HttpError(503, "NOT_INITIALIZED", "Proxy not initialized. Visit /init first.");
  }

  const got = request.headers.get("X-Proxy-Key") || "";
  if (got !== expected) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing or invalid X-Proxy-Key");
  }
}

async function handleStatusPage(env) {
  ensureKvBinding(env);
  const existing = await env.CONFIG.get(KV_PROXY_KEY);
  const initialized = !!existing;

  return new Response(
    htmlPage(
      "API Transform Proxy",
      `<p><b>Initialized:</b> ${initialized ? "yes" : "no"}</p>
       <p><b>Next step:</b> ${
         initialized
           ? "Call <code>POST /invoke</code> with header <code>X-Proxy-Key</code>."
           : "Visit <a href=\"/init\">/init</a> to create your key."
       }</p>
       <p><b>Docs:</b> Send JSON body with <code>upstream</code> and optional <code>transform</code> to <code>POST /invoke</code>.</p>`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

async function handleInitPage(env) {
  ensureKvBinding(env);
  const existing = await env.CONFIG.get(KV_PROXY_KEY);
  if (existing) {
    return new Response(
      htmlPage(
        "Already initialized",
        `<p><b>Status:</b> initialized</p>
         <p>Key already exists and is intentionally not shown again.</p>
         <p>Use <code>POST /rotate</code> with current <code>X-Proxy-Key</code> if you need a new key.</p>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  const key = generateSecret();
  await env.CONFIG.put(KV_PROXY_KEY, key);

  return new Response(
    htmlPage(
      "Proxy key created",
      `<p><b>Status:</b> initialized</p>
       <p>Copy this key now and store it in Bubble as header <code>X-Proxy-Key</code>.</p>
       <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
         key
       )}</pre>
       <p>This key is only shown on first creation.</p>
       <p><b>Next:</b> call <code>POST /invoke</code>.</p>`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

async function handleRotate(request, env) {
  await requireProxyKey(request, env);

  const newKey = generateSecret();
  await env.CONFIG.put(KV_PROXY_KEY, newKey);

  const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
  if (acceptsHtml) {
    return new Response(
      htmlPage(
        "Key rotated",
        `<p>Store this new key in Bubble and replace the old value immediately.</p>
         <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
           newKey
         )}</pre>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return jsonResponse(200, {
    ok: true,
    data: { new_key: newKey },
    meta: { rotated: true },
  });
}

async function handleInvoke(request, env) {
  await requireProxyKey(request, env);
  enforceInvokeContentType(request);

  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const maxResp = getEnvInt(env, "MAX_RESP_BYTES", DEFAULTS.MAX_RESP_BYTES);
  const maxExpr = getEnvInt(env, "MAX_EXPR_BYTES", DEFAULTS.MAX_EXPR_BYTES);
  const transformTimeoutMs = getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS);

  const payload = await readJsonWithLimit(request, maxReq);
  const problems = validateInvokePayload(payload);
  if (problems.length > 0) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid /invoke request payload", {
      expected: EXPECTED_INVOKE_SCHEMA,
      problems,
      received: truncateJsonSnippet(payload),
    });
  }

  let upstreamUrl;
  try {
    upstreamUrl = new URL(payload.upstream.url);
  } catch {
    throw new HttpError(400, "INVALID_REQUEST", "upstream.url must be a valid URL", {
      expected: EXPECTED_INVOKE_SCHEMA,
      problems: ["upstream.url is not a valid URL"],
      received: truncateJsonSnippet(payload),
    });
  }

  const allowedHosts = getAllowedHosts(env);
  assertSafeUpstreamUrl(upstreamUrl, allowedHosts);

  const method = payload.upstream.method.toUpperCase();

  const upstreamHeaders = new Headers();
  if (isPlainObject(payload.upstream.headers)) {
    const hopByHop = new Set(["connection", "host", "content-length", "transfer-encoding"]);
    for (const [k, v] of Object.entries(payload.upstream.headers)) {
      if (!k || hopByHop.has(k.toLowerCase())) continue;
      upstreamHeaders.set(k, String(v));
    }
  }

  let upstreamBody;
  if (method !== "GET" && method !== "HEAD") {
    const body = isPlainObject(payload.upstream.body) ? payload.upstream.body : { type: "none" };
    const bodyType = String(body.type || "none").toLowerCase();

    if (bodyType === "json") {
      upstreamHeaders.set("Content-Type", "application/json");
      upstreamBody = JSON.stringify(body.value ?? {});
    } else if (bodyType === "urlencoded") {
      upstreamHeaders.set("Content-Type", "application/x-www-form-urlencoded");
      if (typeof body.raw === "string") {
        upstreamBody = body.raw;
      } else {
        const params = new URLSearchParams();
        const source = isPlainObject(body.value) ? body.value : {};
        for (const [k, v] of Object.entries(source)) params.append(k, String(v));
        upstreamBody = params.toString();
      }
    } else if (bodyType === "raw") {
      if (typeof body.content_type === "string" && body.content_type) {
        upstreamHeaders.set("Content-Type", body.content_type);
      }
      upstreamBody = typeof body.raw === "string" ? body.raw : "";
    }
  }

  const t0 = Date.now();
  let upstreamResp;
  try {
    upstreamResp = await fetch(upstreamUrl.toString(), {
      method,
      headers: upstreamHeaders,
      body: upstreamBody,
      redirect: "manual",
    });
  } catch (e) {
    throw new HttpError(502, "UPSTREAM_FETCH_FAILED", "Failed to fetch upstream", {
      cause: String(e?.message || e),
    });
  }
  const upstreamMs = Date.now() - t0;

  const responseBytes = await readResponseWithLimit(upstreamResp, maxResp);
  const contentType = getStoredContentType(upstreamResp.headers);
  const textBody = decodeBody(responseBytes);
  let jsonBody = null;
  let parseMs;
  if (looksJson(contentType)) {
    const parseStart = Date.now();
    jsonBody = parseJsonOrNull(textBody);
    parseMs = Date.now() - parseStart;
  }

  const metaBase = {
    status: upstreamResp.status,
    upstream_ms: upstreamMs,
    upstream_headers: toSafeUpstreamHeaders(upstreamResp.headers),
    content_type: contentType || null,
    response_bytes: responseBytes.byteLength,
  };

  const transform = payload.transform;
  if (!transform) {
    if (looksJson(contentType) && jsonBody === null) {
      return apiError(200, "INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase);
    }

    return jsonResponse(200, successEnvelope(jsonBody !== null ? jsonBody : textBody, metaBase));
  }

  const expr = transform.expr;
  const exprBytes = new TextEncoder().encode(expr).byteLength;
  if (exprBytes > maxExpr) {
    throw new HttpError(413, "EXPR_TOO_LARGE", `transform.expr exceeds ${maxExpr} bytes`);
  }

  const runTransform = shouldRunTransform(transform.when, upstreamResp.status, contentType, responseBytes.byteLength);
  if (!runTransform) {
    const data = jsonBody !== null ? jsonBody : textBody;
    return jsonResponse(200, successEnvelope(data, { ...metaBase, skipped: true }));
  }

  if (!looksJson(contentType)) {
    throw new HttpError(422, "NON_JSON_RESPONSE", "Transform requested but upstream response is not JSON", {
      content_type: contentType || null,
    });
  }
  if (jsonBody === null) {
    throw new HttpError(422, "NON_JSON_RESPONSE", "Transform requested but upstream JSON could not be parsed");
  }

  const transformStart = Date.now();
  let output;
  try {
    output = await evalJsonataWithTimeout(
      expr,
      {
        status: upstreamResp.status,
        headers: toSafeUpstreamHeaders(upstreamResp.headers),
        body: jsonBody,
      },
      transformTimeoutMs
    );
  } catch (e) {
    throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed", {
      cause: String(e?.message || e),
    });
  }
  const transformMs = Date.now() - transformStart;

  return jsonResponse(200, successEnvelope(output, { ...metaBase, parse_ms: parseMs, transform_ms: transformMs }));
}

function htmlPage(title, bodyHtml) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 32px; max-width: 820px; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
  </style>
</head>
<body>
  <h2>${escapeHtml(title)}</h2>
  ${bodyHtml}
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
