/**
 * API transform relay for Bubble-style clients.
 *
 * Endpoints:
 * - GET /_apiproxy               : status page (never initializes)
 * - GET /_apiproxy/init          : bootstrap missing keys (shown once on creation)
 * - POST /_apiproxy/request      : authenticated relay + optional JSONata transform
 * - GET /_apiproxy/admin/version : build version info (admin key required)
 * - POST /_apiproxy/admin/rotate : authenticated key rotation (admin key required)
 * - POST /_apiproxy/admin/rotate-admin : authenticated admin key rotation
 * - GET/PUT /_apiproxy/admin/config
 * - POST /_apiproxy/admin/config/validate
 * - POST /_apiproxy/admin/config/test-rule
 */

const KV_PROXY_KEY = "proxy_key";
const KV_ADMIN_KEY = "admin_key";
const KV_PROXY_KEY_OLD = "proxy_key_old";
const KV_PROXY_KEY_OLD_EXPIRES_AT = "proxy_key_old_expires_at";
const KV_ALLOWED_HOSTS = "allowed_hosts";
const KV_CONFIG_YAML = "config_yaml_v1";
const KV_CONFIG_JSON = "config_json_v1";
const KV_ENRICHED_HEADER_PREFIX = "enriched_header:";
const RESERVED_ROOT = "/_apiproxy";
const ADMIN_ROOT = `${RESERVED_ROOT}/admin`;

const DEFAULTS = {
  ALLOWED_HOSTS: "",
  MAX_REQ_BYTES: 256 * 1024,
  MAX_RESP_BYTES: 1024 * 1024,
  MAX_EXPR_BYTES: 16 * 1024,
  TRANSFORM_TIMEOUT_MS: 400,
  ROTATE_OVERLAP_MS: 10 * 60 * 1000,
};

const EXPECTED_REQUEST_SCHEMA = {
  upstream: {
    method: "GET|POST|PUT|PATCH|DELETE",
    url: "https://... (or /path when X-Proxy-Host is provided)",
    headers: "object<string,string> (optional)",
    body: {
      type: "none|json|urlencoded|raw",
      value: "any (optional)",
      raw: "string (optional)",
      content_type: "string (optional)",
    },
  },
};

// Step 1 contract freeze: root config schema (YAML externally, normalized JSON internally).
const CONFIG_SCHEMA_V1 = {
  targetHost: "string|null",
  transform: {
    enabled: "boolean",
    defaultExpr: "string",
    fallback: "passthrough|error|transform_default",
    rules: [
      {
        name: "string",
        status: ["2xx", 422],
        type: "json|text|binary|any",
        headerMatch: { "x-example-header": "value-or-*contains*" },
        expr: "string",
      },
    ],
  },
  header_forwarding: {
    mode: "blacklist|whitelist",
    names: ["header-name"],
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
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);
const INTERNAL_AUTH_HEADERS = new Set(["x-proxy-key", "x-admin-key"]);
const PROXY_HOST_HEADER_NAMES = ["X-Proxy-Host", "XProxyHost"];
const PROXY_HOST_HEADER_NAMES_LOWER = new Set(PROXY_HOST_HEADER_NAMES.map((n) => n.toLowerCase()));
const VALID_FALLBACK_VALUES = new Set(["passthrough", "error", "transform_default"]);
const VALID_TRANSFORM_TYPES = new Set(["json", "text", "binary", "any"]);
const VALID_HEADER_FORWARDING_MODES = new Set(["blacklist", "whitelist"]);
const STATUS_CLASS_PATTERN = /^[1-5]xx$/i;
const DEFAULT_HEADER_FORWARDING_NAMES = [
  ...HOP_BY_HOP_HEADERS,
  ...INTERNAL_AUTH_HEADERS,
  ...PROXY_HOST_HEADER_NAMES_LOWER,
];
const DEFAULT_CONFIG_V1 = {
  targetHost: null,
  transform: {
    enabled: true,
    defaultExpr: "",
    fallback: "passthrough",
    rules: [],
  },
  header_forwarding: {
    mode: "blacklist",
    names: [...DEFAULT_HEADER_FORWARDING_NAMES],
  },
};

let jsonataFactory = null;
let yamlApi = null;

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    try {
      if (pathname === RESERVED_ROOT && request.method === "GET") {
        return await handleStatusPage(env);
      }
      if (pathname === `${RESERVED_ROOT}/init` && request.method === "GET") {
        return await handleInitPage(env);
      }
      if (pathname === `${RESERVED_ROOT}/request` && request.method === "POST") {
        return await handleRequest(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/version` && request.method === "GET") {
        await requireAdminKey(request, env);
        return handleVersion(env);
      }
      if (pathname === `${ADMIN_ROOT}/rotate` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleRotate(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/rotate-admin` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleRotateAdmin(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/hosts` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleHostsGet(env);
      }
      if (pathname === `${ADMIN_ROOT}/hosts` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleHostsPost(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/hosts` && request.method === "DELETE") {
        await requireAdminKey(request, env);
        return await handleHostsDelete(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/config` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleConfigGet(env);
      }
      if (pathname === `${ADMIN_ROOT}/config` && request.method === "PUT") {
        await requireAdminKey(request, env);
        return await handleConfigPut(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/config/validate` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleConfigValidate(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/config/test-rule` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleConfigTestRule(request, env);
      }
      if (pathname === `${ADMIN_ROOT}/headers` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleEnrichedHeadersList(env);
      }
      if (pathname.startsWith(`${ADMIN_ROOT}/headers/`) && request.method === "PUT") {
        await requireAdminKey(request, env);
        const headerName = pathname.slice(`${ADMIN_ROOT}/headers/`.length);
        return await handleEnrichedHeaderPut(request, env, headerName);
      }
      if (pathname.startsWith(`${ADMIN_ROOT}/headers/`) && request.method === "DELETE") {
        await requireAdminKey(request, env);
        const headerName = pathname.slice(`${ADMIN_ROOT}/headers/`.length);
        return await handleEnrichedHeaderDelete(env, headerName);
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

  if ((pathname === RESERVED_ROOT || pathname === `${RESERVED_ROOT}/init`) && err.status >= 500) {
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

async function getManagedAllowedHosts(env) {
  ensureKvBinding(env);
  const raw = await env.CONFIG.get(KV_ALLOWED_HOSTS);
  if (!raw) return new Set();

  try {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return new Set();
    return new Set(
      arr
        .map((s) => String(s).toLowerCase().trim())
        .filter(Boolean)
    );
  } catch {
    return new Set();
  }
}

async function saveManagedAllowedHosts(env, hostsSet) {
  const list = [...hostsSet].sort();
  await env.CONFIG.put(KV_ALLOWED_HOSTS, JSON.stringify(list));
}

async function getEffectiveAllowedHosts(env) {
  const envHosts = getAllowedHosts(env);
  const managedHosts = await getManagedAllowedHosts(env);
  if ((!envHosts || envHosts.size === 0) && managedHosts.size === 0) return null;

  const merged = new Set();
  if (envHosts) for (const h of envHosts) merged.add(h);
  for (const h of managedHosts) merged.add(h);
  return merged;
}

async function loadYamlApi() {
  if (yamlApi) return yamlApi;
  try {
    const mod = await import("yaml");
    yamlApi = {
      parse: mod.parse,
      stringify: mod.stringify,
    };
    if (typeof yamlApi.parse !== "function" || typeof yamlApi.stringify !== "function") {
      throw new Error("yaml parse/stringify not available");
    }
    return yamlApi;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_YAML_DEPENDENCY",
      "yaml dependency is not available in this Worker build.",
      {
        setup: "Ensure yaml is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

function isNonArrayObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function normalizeHeaderName(name) {
  return String(name || "").trim().toLowerCase();
}

function assertValidHeaderName(nameRaw) {
  const decoded = decodeURIComponent(String(nameRaw || ""));
  const normalized = normalizeHeaderName(decoded);
  // RFC 7230 token-style header name.
  if (!normalized || !/^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(normalized)) {
    throw new HttpError(400, "INVALID_HEADER_NAME", "Header name is invalid", {
      expected: "RFC7230 token characters",
      received: String(nameRaw || ""),
    });
  }
  return normalized;
}

function enrichedHeaderKvKey(name) {
  return `${KV_ENRICHED_HEADER_PREFIX}${name}`;
}

function pushProblem(problems, path, message) {
  problems.push({ path, message });
}

function ensureNoUnknownKeys(obj, allowedKeys, path, problems) {
  if (!isNonArrayObject(obj)) return;
  for (const key of Object.keys(obj)) {
    if (!allowedKeys.has(key)) {
      pushProblem(problems, `${path}.${key}`, "unknown field");
    }
  }
}

function validateAndNormalizeStatusList(statusList, path, problems) {
  if (!Array.isArray(statusList) || statusList.length === 0) {
    pushProblem(problems, path, "must be a non-empty array");
    return [];
  }

  const normalized = [];
  for (let i = 0; i < statusList.length; i += 1) {
    const value = statusList[i];
    const itemPath = `${path}[${i}]`;
    if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 100 || value > 599) {
        pushProblem(problems, itemPath, "numeric status must be an integer between 100 and 599");
        continue;
      }
      normalized.push(value);
      continue;
    }
    if (typeof value === "string") {
      const s = value.trim();
      if (!STATUS_CLASS_PATTERN.test(s)) {
        pushProblem(problems, itemPath, "string status must be one of 1xx,2xx,3xx,4xx,5xx");
        continue;
      }
      normalized.push(s.toLowerCase());
      continue;
    }
    pushProblem(problems, itemPath, "must be a number or status class string");
  }

  return normalized;
}

function validateAndNormalizeHeaderMatch(headerMatch, path, problems) {
  if (headerMatch === undefined) return undefined;
  if (!isNonArrayObject(headerMatch)) {
    pushProblem(problems, path, "must be an object when provided");
    return undefined;
  }

  const normalized = {};
  for (const [name, value] of Object.entries(headerMatch)) {
    const normalizedName = normalizeHeaderName(name);
    if (!normalizedName) {
      pushProblem(problems, `${path}.${name}`, "header name must be non-empty");
      continue;
    }
    if (typeof value !== "string" || !value.trim()) {
      pushProblem(problems, `${path}.${name}`, "header match value must be a non-empty string");
      continue;
    }
    normalized[normalizedName] = value.trim();
  }
  return normalized;
}

function validateAndNormalizeTransformRule(rule, index, problems) {
  const path = `transform.rules[${index}]`;
  if (!isNonArrayObject(rule)) {
    pushProblem(problems, path, "must be an object");
    return null;
  }

  ensureNoUnknownKeys(rule, new Set(["name", "status", "type", "headerMatch", "expr"]), path, problems);

  const name = typeof rule.name === "string" ? rule.name.trim() : "";
  if (!name) pushProblem(problems, `${path}.name`, "must be a non-empty string");

  const status = validateAndNormalizeStatusList(rule.status, `${path}.status`, problems);

  const type = typeof rule.type === "string" ? rule.type.trim().toLowerCase() : "";
  if (!VALID_TRANSFORM_TYPES.has(type)) {
    pushProblem(problems, `${path}.type`, "must be one of json, text, binary, any");
  }

  const expr = typeof rule.expr === "string" ? rule.expr : "";
  if (!expr.trim()) {
    pushProblem(problems, `${path}.expr`, "must be a non-empty string");
  }

  const headerMatch = validateAndNormalizeHeaderMatch(rule.headerMatch, `${path}.headerMatch`, problems);

  return {
    name,
    status,
    type: type || "any",
    ...(headerMatch ? { headerMatch } : {}),
    expr,
  };
}

function validateAndNormalizeConfigV1(configInput) {
  const problems = [];
  const input = configInput ?? {};

  if (!isNonArrayObject(input)) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration must be an object", {
      expected: CONFIG_SCHEMA_V1,
      problems: [{ path: "$", message: "root value must be an object" }],
    });
  }

  ensureNoUnknownKeys(input, new Set(["targetHost", "transform", "header_forwarding"]), "$", problems);

  const targetHostRaw = input.targetHost;
  let targetHost = null;
  if (targetHostRaw !== undefined && targetHostRaw !== null) {
    if (typeof targetHostRaw !== "string") {
      pushProblem(problems, "$.targetHost", "must be a string or null");
    } else {
      const normalizedTarget = targetHostRaw.trim();
      targetHost = normalizedTarget || null;
    }
  }

  const transformIn = input.transform ?? {};
  if (!isNonArrayObject(transformIn)) {
    pushProblem(problems, "$.transform", "must be an object when provided");
  }
  if (isNonArrayObject(transformIn)) {
    ensureNoUnknownKeys(transformIn, new Set(["enabled", "defaultExpr", "fallback", "rules"]), "$.transform", problems);
  }

  const enabled = transformIn.enabled === undefined ? true : transformIn.enabled;
  if (typeof enabled !== "boolean") {
    pushProblem(problems, "$.transform.enabled", "must be a boolean");
  }

  const defaultExpr = transformIn.defaultExpr === undefined ? "" : transformIn.defaultExpr;
  if (typeof defaultExpr !== "string") {
    pushProblem(problems, "$.transform.defaultExpr", "must be a string");
  }

  const fallback = transformIn.fallback === undefined ? "passthrough" : String(transformIn.fallback);
  if (!VALID_FALLBACK_VALUES.has(fallback)) {
    pushProblem(problems, "$.transform.fallback", "must be passthrough, error, or transform_default");
  }

  const rulesIn = transformIn.rules === undefined ? [] : transformIn.rules;
  if (!Array.isArray(rulesIn)) {
    pushProblem(problems, "$.transform.rules", "must be an array");
  }
  const rules = Array.isArray(rulesIn)
    ? rulesIn
        .map((rule, index) => validateAndNormalizeTransformRule(rule, index, problems))
        .filter((rule) => rule !== null)
    : [];

  const headerForwardingIn = input.header_forwarding ?? {};
  if (!isNonArrayObject(headerForwardingIn)) {
    pushProblem(problems, "$.header_forwarding", "must be an object when provided");
  }
  if (isNonArrayObject(headerForwardingIn)) {
    ensureNoUnknownKeys(headerForwardingIn, new Set(["mode", "names"]), "$.header_forwarding", problems);
  }

  const mode = headerForwardingIn.mode === undefined ? "blacklist" : String(headerForwardingIn.mode).toLowerCase();
  if (!VALID_HEADER_FORWARDING_MODES.has(mode)) {
    pushProblem(problems, "$.header_forwarding.mode", "must be blacklist or whitelist");
  }

  const namesIn = headerForwardingIn.names === undefined ? DEFAULT_HEADER_FORWARDING_NAMES : headerForwardingIn.names;
  if (!Array.isArray(namesIn)) {
    pushProblem(problems, "$.header_forwarding.names", "must be an array");
  }
  const names = Array.isArray(namesIn)
    ? namesIn
        .map((name, index) => {
          if (typeof name !== "string") {
            pushProblem(problems, `$.header_forwarding.names[${index}]`, "must be a string");
            return "";
          }
          const normalized = normalizeHeaderName(name);
          if (!normalized) {
            pushProblem(problems, `$.header_forwarding.names[${index}]`, "must be non-empty");
            return "";
          }
          return normalized;
        })
        .filter(Boolean)
    : [];

  if (problems.length > 0) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration validation failed", {
      expected: CONFIG_SCHEMA_V1,
      problems,
    });
  }

  return {
    targetHost,
    transform: {
      enabled,
      defaultExpr,
      fallback,
      rules,
    },
    header_forwarding: {
      mode,
      names: [...new Set(names)],
    },
  };
}

async function parseYamlConfigText(yamlText) {
  if (typeof yamlText !== "string" || !yamlText.trim()) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration YAML must be a non-empty string");
  }
  const yaml = await loadYamlApi();
  let parsed;
  try {
    parsed = yaml.parse(yamlText);
  } catch (e) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration YAML could not be parsed", {
      cause: String(e?.message || e),
    });
  }
  return validateAndNormalizeConfigV1(parsed);
}

async function stringifyYamlConfig(configObj) {
  const yaml = await loadYamlApi();
  return yaml.stringify(configObj);
}

async function loadConfigV1(env) {
  ensureKvBinding(env);
  const raw = await env.CONFIG.get(KV_CONFIG_JSON);
  if (!raw) return JSON.parse(JSON.stringify(DEFAULT_CONFIG_V1));

  try {
    const parsed = JSON.parse(raw);
    return validateAndNormalizeConfigV1(parsed);
  } catch {
    throw new HttpError(500, "INVALID_STORED_CONFIG", "Stored configuration is invalid");
  }
}

async function loadConfigYamlV1(env) {
  ensureKvBinding(env);
  const raw = await env.CONFIG.get(KV_CONFIG_YAML);
  if (raw) return raw;
  const config = await loadConfigV1(env);
  return stringifyYamlConfig(config);
}

async function saveConfigFromYamlV1(yamlText, env) {
  ensureKvBinding(env);
  const normalized = await parseYamlConfigText(yamlText);
  await Promise.all([
    env.CONFIG.put(KV_CONFIG_YAML, yamlText),
    env.CONFIG.put(KV_CONFIG_JSON, JSON.stringify(normalized)),
  ]);
  return normalized;
}

async function listEnrichedHeaderNames(env) {
  ensureKvBinding(env);
  const out = [];
  let cursor = undefined;

  while (true) {
    const page = await env.CONFIG.list({
      prefix: KV_ENRICHED_HEADER_PREFIX,
      cursor,
      limit: 1000,
    });
    for (const entry of page.keys || []) {
      const key = String(entry.name || "");
      if (!key.startsWith(KV_ENRICHED_HEADER_PREFIX)) continue;
      out.push(key.slice(KV_ENRICHED_HEADER_PREFIX.length));
    }
    if (!page.list_complete) {
      cursor = page.cursor;
      continue;
    }
    break;
  }

  return out.sort();
}

async function loadEnrichedHeadersMap(env) {
  const names = await listEnrichedHeaderNames(env);
  if (names.length === 0) return {};

  const values = await Promise.all(names.map((name) => env.CONFIG.get(enrichedHeaderKvKey(name))));
  const out = {};
  for (let i = 0; i < names.length; i += 1) {
    const value = values[i];
    if (typeof value === "string") out[names[i]] = value;
  }
  return out;
}

function getHeaderForwardingPolicy(config) {
  const section = isNonArrayObject(config?.header_forwarding) ? config.header_forwarding : DEFAULT_CONFIG_V1.header_forwarding;
  const mode = section.mode === "whitelist" ? "whitelist" : "blacklist";
  const names = Array.isArray(section.names)
    ? section.names.map((n) => normalizeHeaderName(n)).filter(Boolean)
    : DEFAULT_CONFIG_V1.header_forwarding.names;
  return {
    mode,
    namesSet: new Set(names),
  };
}

function shouldForwardIncomingHeader(headerNameLower, policy) {
  // Never forward Worker-auth headers regardless of config policy.
  if (INTERNAL_AUTH_HEADERS.has(headerNameLower)) return false;

  if (policy.mode === "whitelist") {
    return policy.namesSet.has(headerNameLower);
  }
  return !policy.namesSet.has(headerNameLower);
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

async function readTextWithLimit(request, maxBytes) {
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
  return new TextDecoder().decode(concatUint8Arrays(chunks));
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

function validateInvokePayload(payload, { allowMissingUrl = false } = {}) {
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

  if (!allowMissingUrl && (typeof upstream.url !== "string" || upstream.url.trim() === "")) {
    problems.push("upstream.url is required and must be a non-empty string");
  } else if (upstream.url !== undefined && (typeof upstream.url !== "string" || upstream.url.trim() === "")) {
    problems.push("upstream.url must be a non-empty string when provided");
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
      { allowed_hosts_hint: `Set ALLOWED_HOSTS or add via ${ADMIN_ROOT}/hosts` }
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

function matchesStatusToken(status, token) {
  if (typeof token === "number") return status === token;
  if (typeof token !== "string") return false;
  const t = token.trim().toLowerCase();
  if (t === "1xx") return status >= 100 && status < 200;
  if (t === "2xx") return status >= 200 && status < 300;
  if (t === "3xx") return status >= 300 && status < 400;
  if (t === "4xx") return status >= 400 && status < 500;
  if (t === "5xx") return status >= 500 && status < 600;
  if (/^\d+$/.test(t)) return status === Number(t);
  return false;
}

function detectResponseType(contentType) {
  const ct = String(contentType || "").toLowerCase();
  if (!ct) return "binary";
  if (ct.includes("application/json") || ct.includes("+json")) return "json";
  if (ct.startsWith("text/")) return "text";
  if (ct.includes("xml") || ct.includes("javascript")) return "text";
  return "binary";
}

function normalizeHeaderMap(headersLike) {
  const out = {};
  if (!headersLike) return out;
  if (headersLike instanceof Headers) {
    for (const [k, v] of headersLike.entries()) out[k.toLowerCase()] = v;
    return out;
  }
  if (isNonArrayObject(headersLike)) {
    for (const [k, v] of Object.entries(headersLike)) out[String(k).toLowerCase()] = String(v);
  }
  return out;
}

function headerMatchValue(actual, expectedPattern) {
  const actualText = String(actual || "");
  const expected = String(expectedPattern || "");
  if (!expected) return false;
  const a = actualText.toLowerCase();
  const e = expected.toLowerCase();
  if (e.startsWith("*") && e.endsWith("*") && e.length >= 3) {
    return a.includes(e.slice(1, -1));
  }
  return a === e;
}

function ruleMatches(rule, ctx) {
  if (!rule || !ctx) return { matched: false, reasons: ["invalid rule/context"] };
  const reasons = [];

  const hasStatusConstraint = Array.isArray(rule.status) && rule.status.length > 0;
  if (hasStatusConstraint) {
    const statusOk = rule.status.some((token) => matchesStatusToken(ctx.status, token));
    if (!statusOk) reasons.push("status");
  }

  if (rule.type && rule.type !== "any" && rule.type !== ctx.type) {
    reasons.push("type");
  }

  if (rule.headerMatch && isNonArrayObject(rule.headerMatch)) {
    for (const [name, pattern] of Object.entries(rule.headerMatch)) {
      const actual = ctx.headers[name.toLowerCase()] || "";
      if (!headerMatchValue(actual, pattern)) {
        reasons.push(`header:${name.toLowerCase()}`);
      }
    }
  }

  return { matched: reasons.length === 0, reasons };
}

function selectTransformRule(config, ctx) {
  const rules = Array.isArray(config?.transform?.rules) ? config.transform.rules : [];
  const trace = [];

  for (const rule of rules) {
    const result = ruleMatches(rule, ctx);
    trace.push({ rule: rule.name, matched: result.matched, reasons: result.reasons });
    if (result.matched) {
      return { matchedRule: rule, trace };
    }
  }
  return { matchedRule: null, trace };
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
  const out = { error };
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

async function getAdminKey(env) {
  ensureKvBinding(env);
  return env.CONFIG.get(KV_ADMIN_KEY);
}

async function getProxyKeyAuthState(env) {
  ensureKvBinding(env);
  const [current, old, oldExpiresAtRaw] = await Promise.all([
    env.CONFIG.get(KV_PROXY_KEY),
    env.CONFIG.get(KV_PROXY_KEY_OLD),
    env.CONFIG.get(KV_PROXY_KEY_OLD_EXPIRES_AT),
  ]);
  const oldExpiresAt = Number(oldExpiresAtRaw || 0);
  return { current, old, oldExpiresAt };
}

async function requireProxyKey(request, env) {
  const { current, old, oldExpiresAt } = await getProxyKeyAuthState(env);
  if (!current) {
    throw new HttpError(503, "NOT_INITIALIZED", `Proxy not initialized. Visit ${RESERVED_ROOT}/init first.`);
  }

  const got = request.headers.get("X-Proxy-Key") || "";
  if (got === current) return;

  const now = Date.now();
  const oldActive = !!old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now;
  if (oldActive && got === old) return;

  if (!!old && Number.isFinite(oldExpiresAt) && oldExpiresAt <= now) {
    // Lazy cleanup of expired overlap key.
    await Promise.all([
      env.CONFIG.delete(KV_PROXY_KEY_OLD),
      env.CONFIG.delete(KV_PROXY_KEY_OLD_EXPIRES_AT),
    ]);
  }

  if (old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing or invalid X-Proxy-Key (old key overlap is active)");
  }
  throw new HttpError(401, "UNAUTHORIZED", "Missing or invalid X-Proxy-Key");
}

async function requireAdminKey(request, env) {
  const expected = await getAdminKey(env);
  if (!expected) {
    throw new HttpError(
      503,
      "ADMIN_NOT_CONFIGURED",
      "Admin key is not initialized.",
      { setup: `Visit ${RESERVED_ROOT}/init to bootstrap keys.` }
    );
  }

  const got = request.headers.get("X-Admin-Key") || "";
  if (got !== expected) {
    throw new HttpError(401, "UNAUTHORIZED_ADMIN", "Missing or invalid X-Admin-Key");
  }
}

function getProxyHostHeader(request) {
  for (const name of PROXY_HOST_HEADER_NAMES) {
    const v = request.headers.get(name);
    if (v && v.trim()) return v.trim();
  }
  return "";
}

function resolveProxyHostForRequest(request, config) {
  const configuredTarget = typeof config?.targetHost === "string" ? config.targetHost.trim() : "";
  const requestedTarget = getProxyHostHeader(request);

  if (configuredTarget) {
    if (requestedTarget) {
      throw new HttpError(
        409,
        "HOST_OVERRIDE_NOT_ALLOWED",
        "X-Proxy-Host is disabled for this deployment.",
        {
          hint: "Remove X-Proxy-Host or update admin config targetHost.",
        }
      );
    }
    return configuredTarget;
  }

  if (!requestedTarget) {
    throw new HttpError(
      400,
      "MISSING_UPSTREAM_HOST",
      "X-Proxy-Host is required when targetHost is not configured.",
      {
        hint: "Set targetHost in admin config or provide X-Proxy-Host on each request.",
      }
    );
  }

  return requestedTarget;
}

function normalizeHostInput(raw) {
  const input = String(raw || "").trim();
  if (!input) {
    throw new HttpError(400, "INVALID_HOST", "host must be a non-empty string");
  }

  try {
    const u = new URL(input);
    if (u.protocol !== "https:") {
      throw new HttpError(400, "INVALID_HOST", "host URL must use https");
    }
    return u.hostname.toLowerCase();
  } catch {
    if (!/^[a-z0-9.-]+$/i.test(input)) {
      throw new HttpError(400, "INVALID_HOST", "host must be a valid hostname or https URL");
    }
    return input.toLowerCase();
  }
}

function parseProxyHostBaseUrl(proxyHostHeader) {
  const raw = String(proxyHostHeader || "").trim();
  if (!raw) return null;

  try {
    const url = new URL(raw);
    if (url.protocol !== "https:") {
      throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "X-Proxy-Host must use https");
    }
    return `${url.protocol}//${url.host}`;
  } catch {
    const host = normalizeHostInput(raw);
    return `https://${host}`;
  }
}

function resolveUpstreamUrl(rawUrl, proxyHostHeader) {
  const base = parseProxyHostBaseUrl(proxyHostHeader);
  const urlText = typeof rawUrl === "string" ? rawUrl.trim() : "";

  if (!base) {
    if (!urlText) {
      throw new HttpError(400, "INVALID_REQUEST", "upstream.url is required when X-Proxy-Host is not provided");
    }
    return new URL(urlText);
  }

  if (!urlText) return new URL(base);

  // If caller provided an absolute URL, replace host/protocol with header-defined host.
  try {
    const absolute = new URL(urlText);
    return new URL(`${absolute.pathname}${absolute.search}${absolute.hash}`, base);
  } catch {
    return new URL(urlText, base);
  }
}

async function handleStatusPage(env) {
  ensureKvBinding(env);
  const [proxyKey, adminKey] = await Promise.all([env.CONFIG.get(KV_PROXY_KEY), env.CONFIG.get(KV_ADMIN_KEY)]);
  const proxyInitialized = !!proxyKey;
  const adminInitialized = !!adminKey;

  return new Response(
    htmlPage(
      "API Transform Proxy",
      `<p><b>Proxy key initialized:</b> ${proxyInitialized ? "yes" : "no"}</p>
       <p><b>Admin key initialized:</b> ${adminInitialized ? "yes" : "no"}</p>
       <p><b>Next step:</b> ${
         proxyInitialized && adminInitialized
           ? `Call <code>POST ${RESERVED_ROOT}/request</code> with header <code>X-Proxy-Key</code>.`
           : `Visit <a href="${RESERVED_ROOT}/init">${RESERVED_ROOT}/init</a> to bootstrap missing keys.`
       }</p>
       <p><b>Docs:</b> Send JSON body with <code>upstream</code> and optional <code>transform</code> to <code>POST ${RESERVED_ROOT}/request</code>.</p>
       <p><b>Admin:</b> Use <code>${ADMIN_ROOT}/*</code> with header <code>X-Admin-Key</code>.</p>`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

function handleVersion(env) {
  const version = String(env.BUILD_VERSION || "dev");
  return jsonResponse(200, {
    ok: true,
    data: { version },
    meta: {},
  });
}

async function handleHostsGet(env) {
  const managed = await getManagedAllowedHosts(env);
  const envHosts = getAllowedHosts(env);
  const effective = await getEffectiveAllowedHosts(env);
  return jsonResponse(200, {
    ok: true,
    data: {
      managed_hosts: [...managed].sort(),
      env_hosts: envHosts ? [...envHosts].sort() : [],
      effective_hosts: effective ? [...effective].sort() : [],
    },
    meta: {},
  });
}

async function handleHostsPost(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const host = normalizeHostInput(body?.host);

  const managed = await getManagedAllowedHosts(env);
  managed.add(host);
  await saveManagedAllowedHosts(env, managed);

  return jsonResponse(200, {
    ok: true,
    data: { added: host, managed_hosts: [...managed].sort() },
    meta: {},
  });
}

async function handleHostsDelete(request, env) {
  let host = new URL(request.url).searchParams.get("host") || "";
  if (!host) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
    host = body?.host || "";
  }
  const normalized = normalizeHostInput(host);

  const managed = await getManagedAllowedHosts(env);
  managed.delete(normalized);
  await saveManagedAllowedHosts(env, managed);

  return jsonResponse(200, {
    ok: true,
    data: { removed: normalized, managed_hosts: [...managed].sort() },
    meta: {},
  });
}

async function handleConfigGet(env) {
  const yamlText = await loadConfigYamlV1(env);
  return new Response(yamlText, {
    status: 200,
    headers: { "content-type": "text/yaml; charset=utf-8" },
  });
}

async function handleConfigPut(request, env) {
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const yamlText = await readTextWithLimit(request, maxReq);
  const normalized = await saveConfigFromYamlV1(yamlText, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      message: "Configuration updated",
      config: normalized,
    },
    meta: {},
  });
}

async function handleConfigValidate(request, env) {
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const yamlText = await readTextWithLimit(request, maxReq);
  const normalized = await parseYamlConfigText(yamlText);
  return jsonResponse(200, {
    ok: true,
    data: {
      valid: true,
      config: normalized,
    },
    meta: {},
  });
}

async function handleConfigTestRule(request, env) {
  enforceInvokeContentType(request);
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const body = await readJsonWithLimit(request, maxReq);

  let config;
  if (typeof body?.config_yaml === "string" && body.config_yaml.trim()) {
    config = await parseYamlConfigText(body.config_yaml);
  } else if (body?.config && isNonArrayObject(body.config)) {
    config = validateAndNormalizeConfigV1(body.config);
  } else {
    config = await loadConfigV1(env);
  }

  const sample = body?.response;
  if (!isNonArrayObject(sample)) {
    throw new HttpError(400, "INVALID_REQUEST", "response object is required", {
      expected: {
        response: {
          status: 404,
          headers: { "content-type": "application/json" },
          body: { error: "Not found" },
          type: "json",
        },
      },
    });
  }

  const status = Number(sample.status);
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    throw new HttpError(400, "INVALID_REQUEST", "response.status must be an integer 100-599");
  }

  const headers = normalizeHeaderMap(sample.headers);
  const contentType = headers["content-type"] || "";
  const type = sample.type ? String(sample.type).toLowerCase() : detectResponseType(contentType);
  if (!VALID_TRANSFORM_TYPES.has(type)) {
    throw new HttpError(400, "INVALID_REQUEST", "response.type must be one of json, text, binary, any");
  }

  const ctx = { status, headers, type };
  const { matchedRule, trace } = selectTransformRule(config, ctx);

  let expression = null;
  let source = "none";
  if (matchedRule) {
    expression = matchedRule.expr;
    source = `rule:${matchedRule.name}`;
  } else if (config.transform.fallback === "transform_default" && config.transform.defaultExpr) {
    expression = config.transform.defaultExpr;
    source = "defaultExpr";
  }

  let output = null;
  if (expression) {
    try {
      output = await evalJsonataWithTimeout(
        expression,
        { status, headers, body: sample.body },
        getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS)
      );
    } catch (e) {
      throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed in test-rule", {
        cause: String(e?.message || e),
      });
    }
  }

  return jsonResponse(200, {
    ok: true,
    data: {
      matched_rule: matchedRule ? matchedRule.name : null,
      expression_source: source,
      fallback_behavior: config.transform.fallback,
      output,
      trace,
    },
    meta: {},
  });
}

async function handleEnrichedHeadersList(env) {
  const names = await listEnrichedHeaderNames(env);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderPut(request, env, headerNameRaw) {
  enforceInvokeContentType(request);
  const headerName = assertValidHeaderName(headerNameRaw);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = body?.value;
  if (typeof value !== "string" || !value.length) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required and must be a non-empty string", {
      expected: { value: "string" },
    });
  }

  await env.CONFIG.put(enrichedHeaderKvKey(headerName), value);
  const names = await listEnrichedHeaderNames(env);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderDelete(env, headerNameRaw) {
  const headerName = assertValidHeaderName(headerNameRaw);
  const kvKey = enrichedHeaderKvKey(headerName);
  const existing = await env.CONFIG.get(kvKey);
  if (!existing) {
    throw new HttpError(404, "HEADER_NOT_FOUND", "No enriched header exists for the provided name.", {
      name: headerName,
      hint: `List current enriched headers at ${ADMIN_ROOT}/headers.`,
    });
  }
  await env.CONFIG.delete(kvKey);
  const names = await listEnrichedHeaderNames(env);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleInitPage(env) {
  ensureKvBinding(env);
  const [existingProxy, existingAdmin] = await Promise.all([env.CONFIG.get(KV_PROXY_KEY), env.CONFIG.get(KV_ADMIN_KEY)]);
  let createdProxy = null;
  let createdAdmin = null;

  if (!existingProxy) {
    createdProxy = generateSecret();
    await env.CONFIG.put(KV_PROXY_KEY, createdProxy);
  }
  if (!existingAdmin) {
    createdAdmin = generateSecret();
    await env.CONFIG.put(KV_ADMIN_KEY, createdAdmin);
  }

  if (!createdProxy && !createdAdmin) {
    return new Response(
      htmlPage(
        "Already initialized",
        `<p><b>Status:</b> initialized</p>
         <p>Proxy and admin keys already exist and are intentionally not shown again.</p>
         <p>Use <code>POST ${ADMIN_ROOT}/rotate</code> to rotate proxy key and <code>POST ${ADMIN_ROOT}/rotate-admin</code> to rotate admin key.</p>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return new Response(
    htmlPage(
      "Bootstrap complete",
      `<p><b>Status:</b> initialized</p>
       ${
         createdProxy
           ? `<p>Copy this proxy key now and store it as <code>X-Proxy-Key</code>.</p>
       <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
         createdProxy
       )}</pre>`
           : "<p>Proxy key was already initialized and is not shown again.</p>"
       }
       ${
         createdAdmin
           ? `<p>Copy this admin key now and store it as <code>X-Admin-Key</code>.</p>
       <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
         createdAdmin
       )}</pre>`
           : "<p>Admin key was already initialized and is not shown again.</p>"
       }
       <p>These keys are only shown when first created.</p>
       <p><b>Next:</b> call <code>POST ${RESERVED_ROOT}/request</code>.</p>`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

async function handleRotate(request, env) {
  const overlapMs = getEnvInt(env, "ROTATE_OVERLAP_MS", DEFAULTS.ROTATE_OVERLAP_MS);
  const oldExpiresAt = Date.now() + Math.max(0, overlapMs);
  const current = await getProxyKey(env);
  const newKey = generateSecret();
  await env.CONFIG.put(KV_PROXY_KEY, newKey);
  if (current && overlapMs > 0) {
    await Promise.all([
      env.CONFIG.put(KV_PROXY_KEY_OLD, current),
      env.CONFIG.put(KV_PROXY_KEY_OLD_EXPIRES_AT, String(oldExpiresAt)),
    ]);
  } else {
    await Promise.all([
      env.CONFIG.delete(KV_PROXY_KEY_OLD),
      env.CONFIG.delete(KV_PROXY_KEY_OLD_EXPIRES_AT),
    ]);
  }

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
    meta: {
      rotated: true,
      old_key_overlap_active: !!current && overlapMs > 0,
      old_key_overlap_ms: current ? Math.max(0, overlapMs) : 0,
    },
  });
}

async function handleRotateAdmin(request, env) {
  const newAdminKey = generateSecret();
  await env.CONFIG.put(KV_ADMIN_KEY, newAdminKey);

  const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
  if (acceptsHtml) {
    return new Response(
      htmlPage(
        "Admin key rotated",
        `<p>Store this new admin key and replace the old value immediately.</p>
         <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
           newAdminKey
         )}</pre>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return jsonResponse(200, {
    ok: true,
    data: { new_admin_key: newAdminKey },
    meta: { rotated_admin_key: true },
  });
}

async function handleRequest(request, env) {
  await requireProxyKey(request, env);
  enforceInvokeContentType(request);

  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const maxResp = getEnvInt(env, "MAX_RESP_BYTES", DEFAULTS.MAX_RESP_BYTES);
  const maxExpr = getEnvInt(env, "MAX_EXPR_BYTES", DEFAULTS.MAX_EXPR_BYTES);
  const transformTimeoutMs = getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS);

  const config = await loadConfigV1(env);
  const proxyHost = resolveProxyHostForRequest(request, config);
  const headerForwardingPolicy = getHeaderForwardingPolicy(config);
  const payload = await readJsonWithLimit(request, maxReq);
  const problems = validateInvokePayload(payload, { allowMissingUrl: true });
  if (problems.length > 0) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid /request payload", {
      expected: EXPECTED_REQUEST_SCHEMA,
      problems,
      received: truncateJsonSnippet(payload),
    });
  }

  let upstreamUrl;
  try {
    upstreamUrl = resolveUpstreamUrl(payload.upstream.url, proxyHost);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "INVALID_REQUEST", "upstream.url must be a valid URL", {
      expected: EXPECTED_REQUEST_SCHEMA,
      problems: ["upstream.url is not a valid URL"],
      received: truncateJsonSnippet(payload),
    });
  }

  const allowedHosts = await getEffectiveAllowedHosts(env);
  assertSafeUpstreamUrl(upstreamUrl, allowedHosts);

  const method = payload.upstream.method.toUpperCase();

  const upstreamHeaders = new Headers();

  // Start with incoming headers according to config header_forwarding policy.
  for (const [k, v] of request.headers.entries()) {
    const lk = k.toLowerCase();
    if (!shouldForwardIncomingHeader(lk, headerForwardingPolicy)) continue;
    upstreamHeaders.set(k, v);
  }

  // Explicit per-request upstream headers override forwarded incoming headers.
  if (isPlainObject(payload.upstream.headers)) {
    for (const [k, v] of Object.entries(payload.upstream.headers)) {
      if (!k) continue;
      const lk = k.toLowerCase();
      if (INTERNAL_AUTH_HEADERS.has(lk)) continue;
      upstreamHeaders.set(k, String(v));
    }
  }

  // Enriched headers are injected last and win over forwarded/request headers.
  const enrichedHeaders = await loadEnrichedHeadersMap(env);
  for (const [name, value] of Object.entries(enrichedHeaders)) {
    upstreamHeaders.set(name, value);
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
  const responseHeadersMap = normalizeHeaderMap(upstreamResp.headers);
  let jsonBody = null;
  let parseMs;
  let responseType = detectResponseType(contentType);
  if (responseType === "json") {
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

  const transformConfig = config.transform || DEFAULT_CONFIG_V1.transform;
  if (!transformConfig.enabled) {
    if (responseType === "json" && jsonBody === null) {
      return apiError(200, "INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase);
    }
    return jsonResponse(200, successEnvelope(jsonBody !== null ? jsonBody : textBody, metaBase));
  }

  const ruleCtx = {
    status: upstreamResp.status,
    type: responseType,
    headers: responseHeadersMap,
  };
  const { matchedRule, trace } = selectTransformRule(config, ruleCtx);

  let expr = "";
  let transformSource = "none";
  if (matchedRule) {
    expr = matchedRule.expr || "";
    transformSource = `rule:${matchedRule.name}`;
  } else if (transformConfig.fallback === "transform_default" && transformConfig.defaultExpr) {
    expr = transformConfig.defaultExpr;
    transformSource = "defaultExpr";
  } else if (transformConfig.fallback === "passthrough") {
    if (responseType === "json" && jsonBody === null) {
      return apiError(200, "INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase);
    }
    return jsonResponse(
      200,
      successEnvelope(jsonBody !== null ? jsonBody : textBody, {
        ...metaBase,
        skipped: true,
        transform_trace: trace,
      })
    );
  } else {
    throw new HttpError(422, "TRANSFORM_RULE_NOT_MATCHED", "No transform rule matched and fallback is set to error", {
      status: upstreamResp.status,
      type: responseType,
      trace,
    });
  }

  const exprBytes = new TextEncoder().encode(expr).byteLength;
  if (exprBytes > maxExpr) {
    throw new HttpError(413, "EXPR_TOO_LARGE", `transform expression exceeds ${maxExpr} bytes`);
  }

  if (responseType === "json" && jsonBody === null) {
    throw new HttpError(422, "NON_JSON_RESPONSE", "Transform selected but upstream JSON could not be parsed", {
      content_type: contentType || null,
    });
  }

  const transformStart = Date.now();
  let output;
  try {
    output = await evalJsonataWithTimeout(
      expr,
      {
        status: upstreamResp.status,
        headers: responseHeadersMap,
        type: responseType,
        content_type: contentType || null,
        body: responseType === "json" ? jsonBody : textBody,
      },
      transformTimeoutMs
    );
  } catch (e) {
    throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed", {
      cause: String(e?.message || e),
      source: transformSource,
    });
  }
  const transformMs = Date.now() - transformStart;

  return jsonResponse(
    200,
    successEnvelope(output, {
      ...metaBase,
      parse_ms: parseMs,
      transform_ms: transformMs,
      transform_source: transformSource,
      transform_trace: trace,
    })
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
