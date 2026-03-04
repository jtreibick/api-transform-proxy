import jsonata from "jsonata";

/**
 * KV keys
 */
const KV_PROXY_KEY = "proxy_key";

const DEFAULTS = {
  // If empty, allow any public HTTPS host (still blocks private/metadata IPs).
  // You can tighten later with env var ALLOWED_HOSTS="api.vendor.com,graph.microsoft.com"
  ALLOWED_HOSTS: "",
  MAX_REQ_BYTES: 256 * 1024,
  MAX_RESP_BYTES: 1024 * 1024,
  MAX_EXPR_BYTES: 16 * 1024,
  TRANSFORM_TIMEOUT_MS: 400,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Basic routing
    if (path === "/" && request.method === "GET") {
      return await handleSetupPage(env);
    }
    if (path === "/invoke" && request.method === "POST") {
      return await handleInvoke(request, env);
    }
    if (path === "/rotate" && request.method === "POST") {
      return await handleRotate(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

function getEnvInt(env, key, fallback) {
  const v = env[key];
  if (v === undefined || v === null || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function getAllowedHosts(env) {
  const raw = (env.ALLOWED_HOSTS ?? DEFAULTS.ALLOWED_HOSTS).trim();
  if (!raw) return null; // null means "allow any public host"
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

/**
 * Prevent SSRF to private networks + metadata endpoints.
 * - Blocks localhost, RFC1918, link-local, and the AWS metadata IP.
 * - Still allows public HTTPS.
 *
 * Note: DNS rebinding protection (resolving hostname -> IP and validating) is not available in Workers
 * without additional infrastructure. This is a baseline guard; host allowlists are the stronger control.
 */
function assertSafeUpstreamUrl(u, allowedHosts) {
  if (!(u instanceof URL)) u = new URL(u);

  if (u.protocol !== "https:") {
    throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "Upstream URL must be https");
  }

  const hostname = u.hostname.toLowerCase();

  // Host allowlist (recommended)
  if (allowedHosts && !allowedHosts.has(hostname)) {
    throw new HttpError(
      403,
      "UPSTREAM_HOST_NOT_ALLOWED",
      `Upstream host not allowlisted: ${hostname}`
    );
  }

  // Block obvious private/metadata targets by hostname patterns
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw new HttpError(403, "UPSTREAM_HOST_BLOCKED", "localhost is blocked");
  }

  // If hostname is an IP literal, block private ranges.
  // (If it’s a domain that resolves to a private IP, you can’t fully prevent that here—use allowlist.)
  if (isIpLiteral(hostname)) {
    if (isPrivateOrLinkLocalIp(hostname) || hostname === "169.254.169.254") {
      throw new HttpError(403, "UPSTREAM_IP_BLOCKED", "Private/link-local IPs are blocked");
    }
  }

  return u;
}

function isIpLiteral(host) {
  // crude: IPv4 dotted quad only (good enough for v0)
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPrivateOrLinkLocalIp(ip) {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;

  const [a, b] = parts;

  // 10.0.0.0/8
  if (a === 10) return true;
  // 127.0.0.0/8
  if (a === 127) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (link-local)
  if (a === 169 && b === 254) return true;

  return false;
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function readJsonWithLimit(request, maxBytes) {
  const reader = request.body?.getReader();
  if (!reader) return null;

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
  const buf = concatUint8Arrays(chunks);
  const text = new TextDecoder().decode(buf);
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON");
  }
}

function concatUint8Arrays(chunks) {
  const total = chunks.reduce((s, c) => s + c.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}

function generateSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function getOrCreateProxyKey(env) {
  const existing = await env.CONFIG.get(KV_PROXY_KEY);
  if (existing) return { key: existing, created: false };
  const key = generateSecret();
  await env.CONFIG.put(KV_PROXY_KEY, key);
  return { key, created: true };
}

async function requireProxyKey(request, env) {
  const expected = await env.CONFIG.get(KV_PROXY_KEY);
  if (!expected) {
    throw new HttpError(503, "NOT_INITIALIZED", "Proxy not initialized. Visit / to initialize.");
  }
  const got = request.headers.get("X-Proxy-Key") || "";
  if (got !== expected) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing or invalid X-Proxy-Key");
  }
}

function redactHeaders(h) {
  const out = {};
  for (const [k, v] of h.entries()) {
    const lk = k.toLowerCase();
    if (lk === "authorization" || lk === "cookie" || lk === "set-cookie" || lk.includes("token") || lk.includes("secret") || lk.includes("key")) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = v;
    }
  }
  return out;
}

async function handleSetupPage(env) {
  const { key, created } = await getOrCreateProxyKey(env);

  if (!created) {
    return new Response(
      htmlPage("Already initialized", `
        <p><b>Status:</b> initialized ✅</p>
        <p>The proxy key was already created. For safety, it is not shown again.</p>
        <p>If you need a new key, use <code>POST /rotate</code> with your current <code>X-Proxy-Key</code>.</p>
      `),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // Show key exactly once (at creation time)
  return new Response(
    htmlPage("Proxy key created", `
      <p><b>Status:</b> initialized ✅</p>
      <p>Copy this key into Bubble and send it on every request as header <code>X-Proxy-Key</code>.</p>
      <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(key)}</pre>
      <p><b>Next:</b> Bubble should call <code>POST /invoke</code> at this Worker URL.</p>
    `),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
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

async function handleRotate(request, env) {
  await requireProxyKey(request, env);

  const newKey = generateSecret();
  await env.CONFIG.put(KV_PROXY_KEY, newKey);

  return jsonResponse(
    200,
    {
      ok: true,
      new_key: newKey,
      note: "Store this new key in Bubble. The old key is now invalid."
    }
  );
}

async function handleInvoke(request, env) {
  await requireProxyKey(request, env);

  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const maxResp = getEnvInt(env, "MAX_RESP_BYTES", DEFAULTS.MAX_RESP_BYTES);
  const maxExpr = getEnvInt(env, "MAX_EXPR_BYTES", DEFAULTS.MAX_EXPR_BYTES);
  const timeoutMs = getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS);

  const payload = await readJsonWithLimit(request, maxReq);

  if (!payload?.upstream?.url || !payload?.upstream?.method) {
    throw new HttpError(400, "INVALID_REQUEST", "Expected payload.upstream.url and payload.upstream.method");
  }

  const allowedHosts = getAllowedHosts(env);
  const upstreamUrl = assertSafeUpstreamUrl(new URL(payload.upstream.url), allowedHosts);

  const method = String(payload.upstream.method).toUpperCase();
  const headersIn = payload.upstream.headers && typeof payload.upstream.headers === "object" ? payload.upstream.headers : {};

  // Forward only safe headers + explicit ones (v0: forward whatever user gives, but strip hop-by-hop)
  const hopByHop = new Set(["connection", "host", "content-length", "transfer-encoding"]);
  const upstreamHeaders = new Headers();
  for (const [k, v] of Object.entries(headersIn)) {
    if (!k) continue;
    const lk = k.toLowerCase();
    if (hopByHop.has(lk)) continue;
    upstreamHeaders.set(k, String(v));
  }

  // Upstream body handling
  let upstreamBody = undefined;
  if (method !== "GET" && method !== "HEAD") {
    const b = payload.upstream.body || { type: "none" };
    const t = (b.type || "none").toLowerCase();

    if (t === "none") {
      upstreamBody = undefined;
    } else if (t === "json") {
      upstreamHeaders.set("Content-Type", "application/json");
      upstreamBody = JSON.stringify(b.value ?? {});
    } else if (t === "urlencoded") {
      upstreamHeaders.set("Content-Type", "application/x-www-form-urlencoded");
      if (typeof b.raw === "string" && b.raw.length) {
        upstreamBody = b.raw;
      } else {
        const obj = b.value && typeof b.value === "object" ? b.value : {};
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(obj)) params.append(k, String(v));
        upstreamBody = params.toString();
      }
    } else if (t === "raw") {
      if (b.content_type) upstreamHeaders.set("Content-Type", String(b.content_type));
      upstreamBody = typeof b.raw === "string" ? b.raw : "";
    } else {
      throw new HttpError(400, "INVALID_BODY_TYPE", `Unsupported body.type: ${t}`);
    }
  }

  const t0 = Date.now();
  const upstreamResp = await fetch(upstreamUrl.toString(), {
    method,
    headers: upstreamHeaders,
    body: upstreamBody,
  });
  const upstreamMs = Date.now() - t0;

  // Read response with size cap
  const respBuf = await readResponseWithLimit(upstreamResp, maxResp);
  const contentType = (upstreamResp.headers.get("content-type") || "").toLowerCase();

  // Decide whether to run JSONata
  const transform = payload.transform || null;
  if (!transform || transform.mode === "none") {
    // Passthrough JSON only (v0 opinionated). If not JSON, return error wrapper.
    if (!looksJson(contentType)) {
      return jsonResponse(200, {
        ok: false,
        error: { code: "NON_JSON_RESPONSE", message: "Upstream response is not JSON" },
        meta: { status: upstreamResp.status, upstream_ms: upstreamMs }
      });
    }
    const bodyText = new TextDecoder().decode(respBuf);
    let bodyJson;
    try {
      bodyJson = JSON.parse(bodyText);
    } catch {
      return jsonResponse(200, {
        ok: false,
        error: { code: "INVALID_JSON_RESPONSE", message: "Upstream JSON could not be parsed" },
        meta: { status: upstreamResp.status, upstream_ms: upstreamMs }
      });
    }
    return jsonResponse(200, {
      ok: true,
      data: bodyJson,
      meta: { status: upstreamResp.status, upstream_ms: upstreamMs }
    });
  }

  const expr = String(transform.expr || "");
  if (!expr) throw new HttpError(400, "MISSING_EXPR", "transform.expr is required when transform is provided");
  if (expr.length > maxExpr) throw new HttpError(413, "EXPR_TOO_LARGE", `transform.expr exceeds ${maxExpr} bytes`);

  const when = transform.when || null;
  if (when && !shouldRunTransform(when, upstreamResp.status, contentType, respBuf.byteLength)) {
    // Skipped transform: return wrapped passthrough (JSON only).
    if (!looksJson(contentType)) {
      return jsonResponse(200, {
        ok: false,
        error: { code: "TRANSFORM_SKIPPED_NON_JSON", message: "Transform skipped; upstream is not JSON" },
        meta: { status: upstreamResp.status, upstream_ms: upstreamMs, skipped: true }
      });
    }
    const bodyText = new TextDecoder().decode(respBuf);
    let bodyJson;
    try { bodyJson = JSON.parse(bodyText); } catch {
      return jsonResponse(200, {
        ok: false,
        error: { code: "TRANSFORM_SKIPPED_INVALID_JSON", message: "Transform skipped; upstream JSON unparseable" },
        meta: { status: upstreamResp.status, upstream_ms: upstreamMs, skipped: true }
      });
    }
    return jsonResponse(200, {
      ok: true,
      data: bodyJson,
      meta: { status: upstreamResp.status, upstream_ms: upstreamMs, skipped: true }
    });
  }

  // Transform path requires JSON parse
  if (!looksJson(contentType)) {
    return jsonResponse(200, {
      ok: false,
      error: { code: "NON_JSON_RESPONSE", message: "Upstream response is not JSON; cannot run JSONata" },
      meta: { status: upstreamResp.status, upstream_ms: upstreamMs }
    });
  }

  const bodyText = new TextDecoder().decode(respBuf);
  let bodyJson;
  const parseT0 = Date.now();
  try {
    bodyJson = JSON.parse(bodyText);
  } catch {
    return jsonResponse(200, {
      ok: false,
      error: { code: "INVALID_JSON_RESPONSE", message: "Upstream JSON could not be parsed" },
      meta: { status: upstreamResp.status, upstream_ms: upstreamMs }
    });
  }
  const parseMs = Date.now() - parseT0;

  const inputObj = {
    status: upstreamResp.status,
    headers: redactHeaders(upstreamResp.headers),
    body: bodyJson
  };

  // Run JSONata with a time budget
  const txT0 = Date.now();
  let output;
  try {
    output = await evalJsonataWithTimeout(expr, inputObj, timeoutMs);
  } catch (e) {
    return jsonResponse(200, {
      ok: false,
      error: { code: "TRANSFORM_ERROR", message: String(e?.message || e) },
      meta: { status: upstreamResp.status, upstream_ms: upstreamMs, parse_ms: parseMs }
    });
  }
  const txMs = Date.now() - txT0;

  return jsonResponse(200, {
    ok: true,
    data: output,
    meta: { status: upstreamResp.status, upstream_ms: upstreamMs, parse_ms: parseMs, transform_ms: txMs }
  });
}

function looksJson(contentType) {
  return contentType.includes("application/json") || contentType.includes("+json");
}

function shouldRunTransform(when, status, contentType, respBytes) {
  // status allow/deny can include numbers or strings like "2xx", "4xx", "5xx"
  const s = when.status || null;
  if (s) {
    if (Array.isArray(s.deny) && matchesStatusList(status, s.deny)) return false;
    if (Array.isArray(s.allow) && !matchesStatusList(status, s.allow)) return false;
  }

  const ct = when.content_type || null;
  if (ct) {
    if (Array.isArray(ct.deny) && matchesContentType(contentType, ct.deny)) return false;
    if (Array.isArray(ct.allow) && !matchesContentType(contentType, ct.allow)) return false;
  }

  const max = when.max_response_bytes;
  if (typeof max === "number" && respBytes > max) return false;

  return true;
}

function matchesStatusList(status, list) {
  for (const item of list) {
    if (typeof item === "number" && status === item) return true;
    if (typeof item === "string") {
      const t = item.trim().toLowerCase();
      if (t === "2xx" && status >= 200 && status < 300) return true;
      if (t === "3xx" && status >= 300 && status < 400) return true;
      if (t === "4xx" && status >= 400 && status < 500) return true;
      if (t === "5xx" && status >= 500 && status < 600) return true;
      if (/^\d+$/.test(t) && status === Number(t)) return true;
    }
  }
  return false;
}

function matchesContentType(contentType, patterns) {
  const ct = (contentType || "").toLowerCase();
  for (const p of patterns) {
    const pat = String(p).toLowerCase();
    if (pat === "*") return true;
    if (pat.endsWith("*") && ct.startsWith(pat.slice(0, -1))) return true;
    if (ct.includes(pat)) return true;
  }
  return false;
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

async function evalJsonataWithTimeout(exprStr, inputObj, timeoutMs) {
  const expr = jsonata(exprStr);

  // JSONata's JS implementation returns either a value or a promise (depending on functions).
  // We enforce a simple timeout by racing.
  const work = Promise.resolve(expr.evaluate(inputObj));
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`JSONata timeout after ${timeoutMs}ms`)), timeoutMs)
  );
  return await Promise.race([work, timeout]);
}

function jsonResponse(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}