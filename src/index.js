/**
 * API transform relay for Bubble-style clients.
 *
 * Endpoints:
 * - GET /_apiproxy               : status + bootstrap page (shows created keys once)
 * - POST /_apiproxy/request      : authenticated relay + optional JSONata transform
 * - GET /_apiproxy/admin/version : build version info (admin key required)
 * - POST /_apiproxy/admin/rotate : authenticated key rotation (admin key required)
 * - POST /_apiproxy/admin/rotate-admin : authenticated admin key rotation
 * - GET/PUT /_apiproxy/admin/config
 * - POST /_apiproxy/admin/config/validate
 * - POST /_apiproxy/admin/config/test-rule
 * - GET/PUT/DELETE /_apiproxy/admin/debug
 * - GET /_apiproxy/admin/debug/last
 * - PUT/DELETE /_apiproxy/admin/debug/loggingEndpoint
 */

const KV_PROXY_KEY = "proxy_key";
const KV_ADMIN_KEY = "admin_key";
const KV_PROXY_KEY_OLD = "proxy_key_old";
const KV_PROXY_KEY_OLD_EXPIRES_AT = "proxy_key_old_expires_at";
const KV_CONFIG_YAML = "config_yaml_v1";
const KV_CONFIG_JSON = "config_json_v1";
const KV_ENRICHED_HEADER_PREFIX = "enriched_header:";
const KV_BOOTSTRAP_ENRICHED_HEADER_NAMES = "bootstrap_enriched_header_names_v1";
const KV_DEBUG_ENABLED_UNTIL_MS = "debug_enabled_until_ms";
const RESERVED_ROOT = "/_apiproxy";
const ADMIN_ROOT = `${RESERVED_ROOT}/admin`;
const DEFAULT_DOCS_URL = "https://github.com/jtreibick/api-transform-proxy/blob/main/README.md";
const DEBUG_MAX_TRACE_CHARS = 32000;
const DEBUG_MAX_BODY_PREVIEW_CHARS = 4000;

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
  debug: {
    max_ttl_seconds: "integer (1-604800)",
    redact_headers: ["header-name"],
    loggingEndpoint: {
      url: "string|null",
      auth_header: "string|null",
      auth_value: "string|null",
    },
  },
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
  debug: {
    max_ttl_seconds: 3600,
    redact_headers: ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-proxy-key", "x-admin-key"],
    loggingEndpoint: {
      url: null,
      auth_header: null,
      auth_value: null,
    },
  },
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
let lastDebugTrace = null;

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 72 72">
  <rect width="72" height="72" rx="16" fill="#0f172a"/>
  <path d="M24 15L11 24v24l13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M48 15l13 9v24l-13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M39 9L25 36h8l-3 27 16-31h-9z" fill="#22d3ee"/>
</svg>`;

const FAVICON_DATA_URL = `data:image/svg+xml,${encodeURIComponent(FAVICON_SVG)}`;

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    const normalizedPath = normalizePathname(pathname);

    try {
      if (normalizedPath === "/" && request.method === "GET") {
        if (request.headers.get("X-Proxy-Key")) {
          return await handleRootProxyRequest(request, env, ctx);
        }
        return Response.redirect(new URL(`${RESERVED_ROOT}/`, request.url).toString(), 302);
      }
      if (normalizedPath === RESERVED_ROOT && request.method === "GET") {
        return await handleStatusPage(env, request);
      }
      if (normalizedPath === `${RESERVED_ROOT}/request` && request.method === "POST") {
        return await handleRequest(request, env, ctx);
      }
      if (normalizedPath === ADMIN_ROOT && request.method === "GET") {
        return handleAdminPage();
      }
      if (normalizedPath === `${ADMIN_ROOT}/version` && request.method === "GET") {
        await requireAdminKey(request, env);
        return handleVersion(env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/rotate` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleRotate(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/rotate-admin` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleRotateAdmin(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/config` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleConfigGet(env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/config` && request.method === "PUT") {
        await requireAdminKey(request, env);
        return await handleConfigPut(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/config/validate` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleConfigValidate(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/config/test-rule` && request.method === "POST") {
        await requireAdminKey(request, env);
        return await handleConfigTestRule(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleDebugGet(env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug` && request.method === "PUT") {
        await requireAdminKey(request, env);
        return await handleDebugPut(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug` && request.method === "DELETE") {
        await requireAdminKey(request, env);
        return await handleDebugDelete(env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug/last` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleDebugLastGet(request);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug/loggingEndpoint` && request.method === "PUT") {
        await requireAdminKey(request, env);
        return await handleDebugLoggingEndpointPut(request, env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/debug/loggingEndpoint` && request.method === "DELETE") {
        await requireAdminKey(request, env);
        return await handleDebugLoggingEndpointDelete(env);
      }
      if (normalizedPath === `${ADMIN_ROOT}/headers` && request.method === "GET") {
        await requireAdminKey(request, env);
        return await handleEnrichedHeadersList(env);
      }
      if (normalizedPath.startsWith(`${ADMIN_ROOT}/headers/`) && request.method === "PUT") {
        await requireAdminKey(request, env);
        const headerName = normalizedPath.slice(`${ADMIN_ROOT}/headers/`.length);
        return await handleEnrichedHeaderPut(request, env, headerName);
      }
      if (normalizedPath.startsWith(`${ADMIN_ROOT}/headers/`) && request.method === "DELETE") {
        await requireAdminKey(request, env);
        const headerName = normalizedPath.slice(`${ADMIN_ROOT}/headers/`.length);
        return await handleEnrichedHeaderDelete(env, headerName);
      }

      return apiError(404, "NOT_FOUND", "Route not found");
    } catch (error) {
      return renderError(error, normalizedPath);
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

  if (pathname === RESERVED_ROOT && err.status >= 500) {
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

function normalizePathname(pathname) {
  const raw = String(pathname || "/");
  if (raw === "/") return "/";
  const trimmed = raw.replace(/\/+$/, "");
  return trimmed || "/";
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

  ensureNoUnknownKeys(input, new Set(["targetHost", "debug", "transform", "header_forwarding"]), "$", problems);

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

  const debugIn = input.debug ?? {};
  if (!isNonArrayObject(debugIn)) {
    pushProblem(problems, "$.debug", "must be an object when provided");
  }
  if (isNonArrayObject(debugIn)) {
    ensureNoUnknownKeys(debugIn, new Set(["max_ttl_seconds", "redact_headers", "loggingEndpoint"]), "$.debug", problems);
  }
  const maxTtlSecondsRaw = isNonArrayObject(debugIn) ? debugIn.max_ttl_seconds : undefined;
  const maxTtlSeconds = maxTtlSecondsRaw === undefined ? 3600 : Number(maxTtlSecondsRaw);
  if (!Number.isInteger(maxTtlSeconds)) {
    pushProblem(problems, "$.debug.max_ttl_seconds", "must be an integer");
  } else if (maxTtlSeconds < 1 || maxTtlSeconds > 604800) {
    pushProblem(problems, "$.debug.max_ttl_seconds", "must be between 1 and 604800 (7 days)");
  }
  const redactHeadersIn =
    isNonArrayObject(debugIn) && debugIn.redact_headers !== undefined
      ? debugIn.redact_headers
      : DEFAULT_CONFIG_V1.debug.redact_headers;
  if (!Array.isArray(redactHeadersIn)) {
    pushProblem(problems, "$.debug.redact_headers", "must be an array");
  }
  const redactHeaders = Array.isArray(redactHeadersIn)
    ? redactHeadersIn
        .map((name, index) => {
          if (typeof name !== "string") {
            pushProblem(problems, `$.debug.redact_headers[${index}]`, "must be a string");
            return "";
          }
          const normalized = normalizeHeaderName(name);
          if (!normalized) {
            pushProblem(problems, `$.debug.redact_headers[${index}]`, "must be non-empty");
            return "";
          }
          return normalized;
        })
        .filter(Boolean)
    : [...DEFAULT_CONFIG_V1.debug.redact_headers];
  const loggingUrlIn = isNonArrayObject(debugIn) && debugIn.loggingEndpoint !== undefined ? debugIn.loggingEndpoint : {};
  if (!isNonArrayObject(loggingUrlIn)) {
    pushProblem(problems, "$.debug.loggingEndpoint", "must be an object when provided");
  }
  if (isNonArrayObject(loggingUrlIn)) {
    ensureNoUnknownKeys(loggingUrlIn, new Set(["url", "auth_header", "auth_value"]), "$.debug.loggingEndpoint", problems);
  }
  const sinkUrlRaw = isNonArrayObject(loggingUrlIn) ? loggingUrlIn.url : undefined;
  const sinkAuthHeaderRaw = isNonArrayObject(loggingUrlIn) ? loggingUrlIn.auth_header : undefined;
  const sinkAuthValueRaw = isNonArrayObject(loggingUrlIn) ? loggingUrlIn.auth_value : undefined;
  let sinkUrl = null;
  if (sinkUrlRaw !== undefined && sinkUrlRaw !== null) {
    if (typeof sinkUrlRaw !== "string" || !sinkUrlRaw.trim()) {
      pushProblem(problems, "$.debug.loggingEndpoint.url", "must be a non-empty string or null");
    } else {
      sinkUrl = sinkUrlRaw.trim();
      try {
        const u = new URL(sinkUrl);
        if (u.protocol !== "https:") {
          pushProblem(problems, "$.debug.loggingEndpoint.url", "must use https");
        }
      } catch {
        pushProblem(problems, "$.debug.loggingEndpoint.url", "must be a valid URL");
      }
    }
  }
  let sinkAuthHeader = null;
  if (sinkAuthHeaderRaw !== undefined && sinkAuthHeaderRaw !== null) {
    if (typeof sinkAuthHeaderRaw !== "string" || !sinkAuthHeaderRaw.trim()) {
      pushProblem(problems, "$.debug.loggingEndpoint.auth_header", "must be a non-empty string or null");
    } else {
      try {
        sinkAuthHeader = assertValidHeaderName(sinkAuthHeaderRaw.trim());
      } catch {
        pushProblem(problems, "$.debug.loggingEndpoint.auth_header", "must be a valid header name");
      }
    }
  }
  let sinkAuthValue = null;
  if (sinkAuthValueRaw !== undefined && sinkAuthValueRaw !== null) {
    if (typeof sinkAuthValueRaw !== "string" || !sinkAuthValueRaw.trim()) {
      pushProblem(problems, "$.debug.loggingEndpoint.auth_value", "must be a non-empty string or null");
    } else {
      sinkAuthValue = sinkAuthValueRaw;
    }
  }

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
    debug: {
      max_ttl_seconds: maxTtlSeconds,
      redact_headers: [...new Set(redactHeaders)],
      loggingEndpoint: {
        url: sinkUrl,
        auth_header: sinkAuthHeader,
        auth_value: sinkAuthValue,
      },
    },
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
  const bootstrapYaml = typeof env?.BOOTSTRAP_CONFIG_YAML === "string" ? env.BOOTSTRAP_CONFIG_YAML.trim() : "";
  if (bootstrapYaml) {
    let normalized;
    try {
      normalized = await parseYamlConfigText(bootstrapYaml);
    } catch (e) {
      if (e instanceof HttpError && e.code === "INVALID_CONFIG") {
        throw new HttpError(
          500,
          "INVALID_BOOTSTRAP_CONFIG",
          "BOOTSTRAP_CONFIG_YAML is invalid and could not be applied.",
          e.details || null
        );
      }
      throw e;
    }
    const [storedYaml, storedJson] = await Promise.all([env.CONFIG.get(KV_CONFIG_YAML), env.CONFIG.get(KV_CONFIG_JSON)]);
    const normalizedJson = JSON.stringify(normalized);
    if (storedYaml !== bootstrapYaml || storedJson !== normalizedJson) {
      await Promise.all([env.CONFIG.put(KV_CONFIG_YAML, bootstrapYaml), env.CONFIG.put(KV_CONFIG_JSON, normalizedJson)]);
    }
    return normalized;
  }
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
  const bootstrapYaml = typeof env?.BOOTSTRAP_CONFIG_YAML === "string" ? env.BOOTSTRAP_CONFIG_YAML.trim() : "";
  if (bootstrapYaml) {
    return bootstrapYaml;
  }
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

async function saveConfigObjectV1(configObj, env) {
  ensureKvBinding(env);
  const normalized = validateAndNormalizeConfigV1(configObj);
  const yamlText = await stringifyYamlConfig(normalized);
  await Promise.all([
    env.CONFIG.put(KV_CONFIG_YAML, yamlText),
    env.CONFIG.put(KV_CONFIG_JSON, JSON.stringify(normalized)),
  ]);
  return normalized;
}

function toUpperSnakeCase(name) {
  return String(name || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[-\s]+/g, "_")
    .toUpperCase();
}

function resolveTemplateVar(varName, env) {
  const candidates = [String(varName || ""), toUpperSnakeCase(varName)];
  for (const c of candidates) {
    const v = env?.[c];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return null;
}

function resolveTemplateVars(text, env) {
  return String(text).replace(/\$\{([A-Za-z0-9_]+)\}/g, (_m, varName) => {
    const value = resolveTemplateVar(varName, env);
    if (value === null) {
      throw new HttpError(500, "MISSING_BOOTSTRAP_SECRET", "A referenced bootstrap secret variable is missing.", {
        variable: varName,
      });
    }
    return value;
  });
}

function parseBootstrapEnrichedHeadersJson(raw, env) {
  const input = String(raw || "").trim();
  if (!input) return {};

  let parsed;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON is not valid JSON.", {
      cause: String(e?.message || e),
    });
  }
  if (!isPlainObject(parsed)) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON must be a JSON object.");
  }

  const out = {};
  for (const [name, value] of Object.entries(parsed)) {
    const normalized = assertValidHeaderName(name);
    if (typeof value !== "string") {
      throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "Each bootstrap header value must be a string.", {
        header: normalized,
      });
    }
    out[normalized] = resolveTemplateVars(value, env);
  }
  return out;
}

function getBootstrapEnrichedHeaders(env) {
  return parseBootstrapEnrichedHeadersJson(env?.BOOTSTRAP_ENRICHED_HEADERS_JSON, env);
}

async function syncBootstrapEnrichedHeaders(env, managedHeaders) {
  ensureKvBinding(env);
  const names = Object.keys(managedHeaders || {});
  const prevRaw = await env.CONFIG.get(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES);
  let prev = [];
  try {
    const parsed = JSON.parse(prevRaw || "[]");
    if (Array.isArray(parsed)) prev = parsed.map((n) => normalizeHeaderName(n)).filter(Boolean);
  } catch {
    prev = [];
  }
  const prevSet = new Set(prev);
  const nextSet = new Set(names);

  const deletes = [];
  for (const name of prevSet) {
    if (!nextSet.has(name)) deletes.push(env.CONFIG.delete(enrichedHeaderKvKey(name)));
  }

  const gets = await Promise.all(names.map((name) => env.CONFIG.get(enrichedHeaderKvKey(name))));
  const puts = [];
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i];
    const desired = managedHeaders[name];
    if (gets[i] !== desired) {
      puts.push(env.CONFIG.put(enrichedHeaderKvKey(name), desired));
    }
  }

  const prevSorted = [...prevSet].sort();
  const nextSorted = [...nextSet].sort();
  const namesChanged = prevSorted.length !== nextSorted.length || prevSorted.some((n, i) => n !== nextSorted[i]);
  const ops = [...deletes, ...puts];
  if (namesChanged) {
    ops.push(env.CONFIG.put(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES, JSON.stringify(nextSorted)));
  }
  if (ops.length > 0) {
    await Promise.all(ops);
  }
}

async function listEnrichedHeaderNames(env, managedHeaders = null) {
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

  if (managedHeaders && isPlainObject(managedHeaders)) {
    for (const name of Object.keys(managedHeaders)) out.push(name);
  }

  return [...new Set(out)].sort();
}

async function loadEnrichedHeadersMap(env) {
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  await syncBootstrapEnrichedHeaders(env, managedHeaders);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  if (names.length === 0) return {};

  const values = await Promise.all(names.map((name) => env.CONFIG.get(enrichedHeaderKvKey(name))));
  const out = {};
  for (let i = 0; i < names.length; i += 1) {
    const value = values[i];
    if (typeof value === "string") out[names[i]] = value;
  }
  for (const [name, value] of Object.entries(managedHeaders)) {
    out[name] = value;
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
      { allowed_hosts_hint: "Set ALLOWED_HOSTS with a comma-separated host allowlist." }
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

function jsonResponse(status, body, extraHeaders = null) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
  };
  if (extraHeaders && typeof extraHeaders === "object") {
    for (const [k, v] of Object.entries(extraHeaders)) {
      if (!k || v === undefined || v === null) continue;
      headers[k] = String(v);
    }
  }
  return new Response(JSON.stringify(body), {
    status,
    headers,
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
    throw new HttpError(503, "NOT_INITIALIZED", `Proxy not initialized. Visit ${RESERVED_ROOT} first.`);
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
      { setup: `Visit ${RESERVED_ROOT} to bootstrap keys.` }
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

async function handleStatusPage(env, request) {
  ensureKvBinding(env);
  const [proxyKey, adminKey] = await Promise.all([env.CONFIG.get(KV_PROXY_KEY), env.CONFIG.get(KV_ADMIN_KEY)]);
  const proxyInitialized = !!proxyKey;
  const adminInitialized = !!adminKey;
  if (!proxyInitialized || !adminInitialized) {
    return handleInitPage(env, request);
  }
  const testingDocsUrl = getDocsSectionUrl(env, "testing-out-your-proxy");
  const keyManagementDocsUrl = getDocsSectionUrl(env, "key-management");

  return new Response(
    htmlPage(
      "API Transform Proxy",
      `<p><b>Status:</b> 🟢 Running</p>
       ${renderSecretField(
         "Admin API Secret (To administer this proxy)",
         "••••••••••••••••••••••••••••••••",
         "admin-api-secret-status",
         `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
           keyManagementDocsUrl
         )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         false
       )}
       ${renderSecretField(
         "Requestor API Secret (To call endpoints through this proxy)",
         "••••••••••••••••••••••••••••••••",
         "proxy-api-secret-status",
         `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
           keyManagementDocsUrl
         )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         false
       )}
       <p><b>How to reset keys</b><br />
       <a href="${escapeHtml(keyManagementDocsUrl)}" target="_blank" rel="noopener noreferrer">Rotating keys</a></p>
       <p><b>How to test</b><br />
       <a href="${escapeHtml(testingDocsUrl)}" target="_blank" rel="noopener noreferrer">Testing out your proxy</a></p>
       ${renderSecretFieldScript()}`
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

async function readDebugEnabledUntilMs(env) {
  ensureKvBinding(env);
  const raw = await env.CONFIG.get(KV_DEBUG_ENABLED_UNTIL_MS);
  const value = Number(raw);
  return Number.isFinite(value) ? value : 0;
}

async function isDebugEnabled(env) {
  const until = await readDebugEnabledUntilMs(env);
  return until > Date.now();
}

function redactDebugValue(value) {
  let text = String(value ?? "");
  text = text.replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer ***REDACTED***");
  text = text.replace(/(\"(?:token|secret|password|api[_-]?key|authorization)\"\s*:\s*\")([^\"]+)(\")/gi, '$1***REDACTED***$3');
  return text;
}

function getDebugRedactHeaderSet(config) {
  const builtIn = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-proxy-key",
    "x-admin-key",
  ];
  const custom = Array.isArray(config?.debug?.redact_headers)
    ? config.debug.redact_headers.map((h) => normalizeHeaderName(h)).filter(Boolean)
    : [];
  return new Set([...builtIn, ...custom]);
}

function toRedactedHeaderMap(headersLike, redactedHeadersSet = null) {
  const sensitive = redactedHeadersSet || new Set([
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-proxy-key",
    "x-admin-key",
  ]);
  const map = normalizeHeaderMap(headersLike);
  const out = {};
  for (const [k, v] of Object.entries(map)) {
    const lk = k.toLowerCase();
    const maybeSensitive = sensitive.has(lk) || lk.includes("token") || lk.includes("secret") || lk.includes("key");
    out[lk] = maybeSensitive ? "***REDACTED***" : redactDebugValue(v);
  }
  return out;
}

function previewBodyForDebug(value) {
  let text = "";
  if (value === undefined || value === null) {
    text = "";
  } else if (typeof value === "string") {
    text = value;
  } else {
    try {
      text = JSON.stringify(value);
    } catch {
      text = String(value);
    }
  }
  text = redactDebugValue(text);
  if (text.length > DEBUG_MAX_BODY_PREVIEW_CHARS) {
    return `${text.slice(0, DEBUG_MAX_BODY_PREVIEW_CHARS)}...(truncated)`;
  }
  return text;
}

function fmtTs(date = new Date()) {
  return date.toISOString();
}

function sectionText(title, timestamp, lines) {
  const body = Array.isArray(lines) ? lines.filter(Boolean).join("\n") : String(lines || "");
  return `----- ${title} -----\nTimestamp: ${timestamp}\n${body}\n`;
}

function buildDebugTraceText(trace) {
  const parts = [
    sectionText("INBOUND REQUEST", trace.inbound.timestamp, [
      `Method: ${trace.inbound.method}`,
      `Path: ${trace.inbound.path}`,
      `Headers: ${JSON.stringify(trace.inbound.headers, null, 2)}`,
      `Body Preview: ${trace.inbound.body_preview}`,
    ]),
    sectionText("OUTBOUND REQUEST (to target)", trace.outbound.timestamp, [
      `URL: ${trace.outbound.url}`,
      `Method: ${trace.outbound.method}`,
      `Headers: ${JSON.stringify(trace.outbound.headers, null, 2)}`,
      `Body Preview: ${trace.outbound.body_preview}`,
    ]),
    sectionText("TARGET RESPONSE (native)", trace.target_response.timestamp, [
      `Status: ${trace.target_response.status}`,
      `Headers: ${JSON.stringify(trace.target_response.headers, null, 2)}`,
      `Body Preview: ${trace.target_response.body_preview}`,
    ]),
    sectionText("TRANSFORM", trace.transform.timestamp, [
      `Action: ${trace.transform.action}`,
      `Matched Rule: ${trace.transform.matched_rule || "none"}`,
      `Expression Source: ${trace.transform.expression_source || "none"}`,
      `Output Preview: ${trace.transform.output_preview}`,
    ]),
    sectionText("FINAL RESPONSE (to requester)", trace.final_response.timestamp, [
      `HTTP Status: ${trace.final_response.http_status}`,
      `Body Preview: ${trace.final_response.body_preview}`,
    ]),
  ];
  const text = parts.join("\n");
  return text.length > DEBUG_MAX_TRACE_CHARS ? `${text.slice(0, DEBUG_MAX_TRACE_CHARS)}\n...(truncated)` : text;
}

async function pushDebugTraceToLoggingUrl(traceText, traceData, config) {
  const sink = config?.debug?.loggingEndpoint || {};
  const url = typeof sink.url === "string" ? sink.url.trim() : "";
  if (!url) return { attempted: false, ok: true };
  const headers = { "content-type": "application/json" };
  if (sink.auth_header && sink.auth_value) {
    headers[sink.auth_header] = String(sink.auth_value);
  }
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        trace_text: traceText,
        trace: traceData,
      }),
    });
    if (!res.ok) {
      return {
        attempted: true,
        ok: false,
        error_code: "SINK_HTTP_ERROR",
        status: res.status,
      };
    }
    return { attempted: true, ok: true };
  } catch {
    return {
      attempted: true,
      ok: false,
      error_code: "SINK_FETCH_FAILED",
    };
  }
}

async function handleDebugLastGet(request) {
  const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
  if (!lastDebugTrace) {
    if (acceptsHtml) {
      return new Response(
        htmlPage("Last Debug Trace", "<p>No debug trace has been captured in this Worker instance yet.</p>"),
        { headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }
    return jsonResponse(200, {
      ok: true,
      data: { available: false },
      meta: {},
    });
  }
  if (acceptsHtml) {
    return new Response(
      htmlPage(
        "Last Debug Trace",
        `<pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">${escapeHtml(
          lastDebugTrace.text
        )}</pre>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }
  return new Response(lastDebugTrace.text, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

async function handleDebugLoggingEndpointPut(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const config = await loadConfigV1(env);
  const sinkInput = body?.loggingEndpoint || {};
  if (!isPlainObject(sinkInput)) {
    throw new HttpError(400, "INVALID_REQUEST", "loggingEndpoint must be an object", {
      expected: { loggingEndpoint: { url: "https://...", auth_header: "x-api-key", auth_value: "value" } },
    });
  }
  const next = JSON.parse(JSON.stringify(config));
  next.debug = next.debug || {};
  next.debug.loggingEndpoint = {
    url: sinkInput.url ?? null,
    auth_header: sinkInput.auth_header ?? null,
    auth_value: sinkInput.auth_value ?? null,
  };
  const saved = await saveConfigObjectV1(next, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      debug_loggingEndpoint: {
        url: saved.debug.loggingEndpoint.url,
        auth_header: saved.debug.loggingEndpoint.auth_header,
        auth_value_set: !!saved.debug.loggingEndpoint.auth_value,
      },
    },
    meta: {},
  });
}

async function handleDebugLoggingEndpointDelete(env) {
  const config = await loadConfigV1(env);
  const next = JSON.parse(JSON.stringify(config));
  next.debug = next.debug || {};
  next.debug.loggingEndpoint = {
    url: null,
    auth_header: null,
    auth_value: null,
  };
  const saved = await saveConfigObjectV1(next, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      debug_loggingEndpoint: {
        url: saved.debug.loggingEndpoint.url,
        auth_header: saved.debug.loggingEndpoint.auth_header,
        auth_value_set: !!saved.debug.loggingEndpoint.auth_value,
      },
    },
    meta: {},
  });
}

function handleAdminPage() {
  return new Response(
    htmlPage(
      "Admin Console",
      `<div style="margin-bottom:10px;">
         <img src="${FAVICON_DATA_URL}" width="48" height="48" alt="API Transform Proxy icon" />
       </div>
       <div id="saved-storage-warning" style="display:none;padding:10px 12px;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:8px;margin:10px 0;">
         ⛔️ Admin key saved on this device. Remove it when done.
         <a href="#" id="remove-local-key-link" style="color:#991b1b;text-decoration:underline;">Remove it</a>
       </div>
       <p>Authenticate with your admin key to access proxy administration tools.</p>
       <div id="admin-warning" style="display:none;padding:10px 12px;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:8px;margin:10px 0;"></div>
       <div id="admin-auth" style="margin:12px 0;">
         <label for="admin-key" style="display:block;font-weight:700;margin-bottom:6px;">Admin API Key</label>
         <input id="admin-key" type="password" placeholder="paste X-Admin-Key"
           style="width:100%;max-width:560px;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;" />
         <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
           <button type="button" id="connect-btn"
             style="padding:8px 12px;border:1px solid #0f172a;border-radius:8px;background:#111827;color:#fff;cursor:pointer;">Connect</button>
           <label for="save-key-local" style="display:inline-flex;align-items:center;gap:8px;cursor:pointer;">
             <input id="save-key-local" type="checkbox" />
             <span>Save Admin API Key Locally (Auto Login)</span>
           </label>
         </div>
       </div>
       <div id="admin-shell" style="display:none;">
         <div style="display:flex;gap:14px;align-items:flex-start;margin:14px 0;">
         <div id="admin-nav" style="display:flex;flex-direction:column;gap:8px;min-width:220px;">
           <button type="button" class="tab-btn" data-tab="overview">Status</button>
           <button type="button" class="tab-btn" data-tab="config">Config</button>
           <button type="button" class="tab-btn" data-tab="debug">Debug</button>
           <button type="button" class="tab-btn" data-tab="headers">Enrichments</button>
           <button type="button" class="tab-btn" data-tab="keys">API Access Keys</button>
         </div>
         <div style="flex:1;min-width:0;">
         <div id="tab-overview" class="tab-panel">
           <p><b>Status</b></p>
           <p><b>Config YAML (source of truth)</b></p>
           <pre id="overview-config-output" style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;">Click "Refresh status".</pre>
           <p><b>Operational status (live runtime)</b></p>
           <pre id="overview-output" style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">Click "Refresh status".</pre>
           <button type="button" id="overview-refresh-btn">Refresh status</button>
         </div>
         <div id="tab-debug" class="tab-panel" style="display:none;">
           <p><b>Debug controls</b></p>
           <label for="ttl-seconds" style="display:block;margin:8px 0 6px;">TTL seconds</label>
           <input id="ttl-seconds" type="number" min="1" step="1" value="3600"
             style="width:220px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />
           <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
             <button type="button" id="debug-refresh-btn">Refresh status</button>
             <button type="button" id="debug-enable-btn">Enable debug</button>
             <button type="button" id="debug-disable-btn">Disable debug</button>
             <button type="button" id="debug-load-trace-btn">Load last trace</button>
           </div>
           <p style="margin-top:16px;"><b>Debug logging</b></p>
           <label for="logging-url" style="display:block;margin:8px 0 4px;">Logging Endpoint URL</label>
           <input id="logging-url" type="text" placeholder="https://example.com/log"
             style="width:100%;max-width:620px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:8px;" />
           <label for="logging-auth-header" style="display:block;margin:2px 0 4px;">Logging Auth Header (optional)</label>
           <input id="logging-auth-header" type="text" placeholder="x-api-key (optional)"
             style="width:100%;max-width:620px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:8px;" />
           <label for="logging-auth-value" style="display:block;margin:2px 0 4px;">Logging Auth Value (optional)</label>
           <input id="logging-auth-value" type="password" placeholder="secret value (optional)"
             style="width:100%;max-width:620px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:8px;" />
           <div style="display:flex;gap:8px;flex-wrap:wrap;">
             <button type="button" id="logging-save-btn">Save logging</button>
             <button type="button" id="logging-delete-btn">Delete logging</button>
           </div>
           <pre id="logging-output" style="margin-top:10px;padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">Logging output appears here.</pre>
           <pre id="debug-output" style="margin-top:10px;padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;">Debug output appears here.</pre>
         </div>
         <div id="tab-config" class="tab-panel" style="display:none;">
           <p><b>YAML config</b></p>
           <textarea id="config-yaml" rows="14"
             style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"></textarea>
           <p id="config-validation-error" style="display:none;margin:6px 0 0;color:#b91c1c;font-size:14px;"></p>
           <div style="margin-top:8px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
             <button type="button" id="config-save-btn">Save</button>
             <a href="#" id="config-reload-link">Reload config</a>
             <a href="#" id="config-test-rule-link">Test rule</a>
           </div>
           <p style="margin:10px 0 6px;"><b>Test rule payload (JSON)</b></p>
           <textarea id="config-test-rule-input" rows="8"
             style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">{"sample":{"status":500,"headers":{"content-type":"application/json"},"type":"json","body":{"error":"bad"}}}</textarea>
           <pre id="config-output" style="margin-top:10px;padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">Config output appears here.</pre>
         </div>
        <div id="tab-headers" class="tab-panel" style="display:none;">
           <p><b>Enrichments</b></p>
           <input id="header-name" type="text" placeholder="authorization"
             style="width:100%;max-width:460px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:8px;" />
           <input id="header-value" type="password" placeholder="header secret value"
             style="width:100%;max-width:460px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:8px;" />
           <div style="display:flex;gap:8px;flex-wrap:wrap;">
             <button type="button" id="headers-list-btn">List headers</button>
             <button type="button" id="headers-save-btn">Set header</button>
             <button type="button" id="headers-delete-btn">Delete header</button>
           </div>
           <pre id="headers-output" style="margin-top:10px;padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">Header output appears here.</pre>
         </div>
         <div id="tab-keys" class="tab-panel" style="display:none;">
           <p><b>Key rotation</b></p>
           <div style="display:flex;gap:8px;flex-wrap:wrap;">
             <button type="button" id="rotate-proxy-btn">Rotate proxy key</button>
             <button type="button" id="rotate-admin-btn">Rotate admin key</button>
           </div>
           <pre id="keys-output" style="margin-top:10px;padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">Rotation output appears here.</pre>
         </div>
         </div>
         </div>
       </div>
       <dialog id="save-key-modal" style="max-width:560px;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
         <p style="margin-top:0;"><b>Save admin key on this device?</b></p>
         <p style="margin:8px 0;">Saving this admin key stores it in this browser profile on this device.</p>
         <p style="margin:8px 0;">Anyone with access to this machine/profile can use it to view sensitive traces and modify proxy settings.</p>
         <ul style="margin:8px 0 8px 20px;">
           <li>Anyone with this key can change routing/config and break your proxy behavior.</li>
           <li>Anyone with this key can view debug traces and potentially access sensitive request/response data.</li>
           <li>Anyone with this key can rotate keys and lock out legitimate operators.</li>
         </ul>
         <p style="margin:8px 0;">If this key is exposed, rotate it immediately.</p>
         <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px;">
           <button type="button" id="save-key-cancel-btn">Cancel</button>
           <button type="button" id="save-key-confirm-btn">I Understand, Save</button>
         </div>
       </dialog>
       <script>
         const ADMIN_ROOT = '${ADMIN_ROOT}';
         const ADMIN_KEY_STORAGE = 'apiproxy_admin_key_v1';
         const DEFAULT_CONFIG_YAML_TEMPLATE = \`targetHost: null
debug:
  max_ttl_seconds: 3600
  redact_headers:
    - authorization
    - proxy-authorization
    - cookie
    - set-cookie
    - x-proxy-key
    - x-admin-key
  loggingEndpoint:
    url: null
    auth_header: null
    auth_value: null
transform:
  enabled: true
  defaultExpr: ""
  fallback: passthrough
  rules: []
header_forwarding:
  mode: blacklist
  names:
    - connection
    - keep-alive
    - proxy-authenticate
    - proxy-authorization
    - te
    - trailer
    - transfer-encoding
    - upgrade
    - host
    - content-length
    - x-proxy-key
    - x-admin-key
    - x-proxy-host
    - xproxyhost
\`;
         let currentKey = '';
         let pendingLocalSaveApproval = false;

         function el(id) { return document.getElementById(id); }
         function setOutput(id, data) {
           const node = el(id);
           if (!node) return;
           node.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
         }
         function showWarning(message) {
           const node = el('admin-warning');
           if (!node) return;
           node.textContent = message || '';
           node.style.display = message ? 'block' : 'none';
         }
         function readKeyInput() {
           return (el('admin-key')?.value || '').trim();
         }
         function saveKeyChecked() {
           return !!el('save-key-local')?.checked;
         }
         function setSaveKeyChecked(checked) {
           if (el('save-key-local')) el('save-key-local').checked = !!checked;
         }
         function updateSavedWarning() {
           const savedWarning = el('saved-storage-warning');
           if (!savedWarning) return;
           savedWarning.style.display = localStorage.getItem(ADMIN_KEY_STORAGE) ? 'block' : 'none';
         }
         function setConfigValidationError(message) {
           const field = el('config-yaml');
           const msg = el('config-validation-error');
           const text = String(message || '').trim();
           if (field) {
             field.style.borderColor = text ? '#dc2626' : '#cbd5e1';
             field.style.background = text ? '#fff5f5' : '#fff';
           }
           if (msg) {
             msg.style.display = text ? 'block' : 'none';
             msg.textContent = text;
           }
         }
         function extractApiErrorText(payload, fallback) {
           if (payload && typeof payload === 'object' && payload.error && typeof payload.error === 'object') {
             const code = payload.error.code ? String(payload.error.code) : 'ERROR';
             const message = payload.error.message ? String(payload.error.message) : String(fallback || 'Request failed');
             return code + ': ' + message;
           }
           return String(fallback || 'Request failed');
         }
         function formatConfigSummary(action, payload) {
           if (!payload || typeof payload !== 'object') {
             return action + '\\n\\n' + String(payload ?? '');
           }
           if (payload.ok === true && payload.data && typeof payload.data === 'object') {
             const lines = [action, ''];
             if (typeof payload.data.message === 'string' && payload.data.message) {
               lines.push('Message: ' + payload.data.message);
             }
             if (typeof payload.data.valid === 'boolean') {
               lines.push('Valid: ' + (payload.data.valid ? 'yes' : 'no'));
             }
             if (payload.data.matched_rule !== undefined) {
               lines.push('Matched rule: ' + (payload.data.matched_rule || 'none'));
             }
             if (payload.data.expression_source !== undefined) {
               lines.push('Expression source: ' + String(payload.data.expression_source || 'none'));
             }
             if (payload.data.fallback_behavior !== undefined) {
               lines.push('Fallback behavior: ' + String(payload.data.fallback_behavior));
             }
             if (payload.data.trace) {
               lines.push('Trace included: yes');
             }
             if (payload.data.output !== undefined) {
               lines.push('Output preview:');
               try {
                 lines.push(JSON.stringify(payload.data.output, null, 2));
               } catch {
                 lines.push(String(payload.data.output));
               }
             }
             return lines.join('\\n');
           }
           return action + '\\n\\n' + JSON.stringify(payload, null, 2);
         }
         function setCurrentKey(key, fromStorage) {
           currentKey = String(key || '').trim();
           const shell = el('admin-shell');
           const auth = el('admin-auth');
           if (shell) shell.style.display = currentKey ? 'block' : 'none';
           if (auth) auth.style.display = currentKey ? 'none' : 'block';
           if (!currentKey) {
             showWarning('');
             updateSavedWarning();
             return;
           }
           updateSavedWarning();
           if (fromStorage) showWarning('Using key saved on this device. If this machine is shared, remove it.');
         }
         function clearSavedKey() {
           localStorage.removeItem(ADMIN_KEY_STORAGE);
           setSaveKeyChecked(false);
           updateSavedWarning();
         }
         function handleUnauthorized() {
           clearSavedKey();
           currentKey = '';
           if (el('admin-key')) el('admin-key').value = '';
           if (el('admin-shell')) el('admin-shell').style.display = 'none';
           if (el('admin-auth')) el('admin-auth').style.display = 'block';
           showWarning('Admin key is invalid or expired. Re-enter X-Admin-Key.');
         }
         async function apiCall(path, method, body, expectText) {
           if (!currentKey) {
             throw new Error('Provide an Admin API Key first.');
           }
           const headers = { 'X-Admin-Key': currentKey };
           if (body !== undefined && !expectText) headers['Content-Type'] = 'application/json';
           if (expectText) headers['Accept'] = 'text/plain';
           const res = await fetch(path, {
             method,
             headers,
             body: body === undefined ? undefined : (expectText ? body : JSON.stringify(body)),
           });
           if (res.status === 401) {
             handleUnauthorized();
             throw new Error('Unauthorized (401)');
           }
           const text = await res.text();
           if (expectText) return text;
           try { return JSON.parse(text); } catch { return text; }
         }
         function attachTabs() {
           const btns = document.querySelectorAll('.tab-btn');
           const panels = document.querySelectorAll('.tab-panel');
           function setActiveTab(name) {
             panels.forEach((panel) => {
               panel.style.display = panel.id === 'tab-' + name ? 'block' : 'none';
             });
             btns.forEach((btn) => {
               const active = btn.getAttribute('data-tab') === name;
               btn.style.background = active ? '#111827' : '#fff';
               btn.style.color = active ? '#fff' : '#0f172a';
               btn.style.borderColor = active ? '#111827' : '#cbd5e1';
               btn.style.fontWeight = active ? '700' : '500';
             });
           }
           btns.forEach((btn) => {
             btn.style.padding = '8px 10px';
             btn.style.border = '1px solid #cbd5e1';
             btn.style.borderRadius = '8px';
             btn.style.background = '#fff';
             btn.style.textAlign = 'left';
             btn.style.cursor = 'pointer';
             btn.addEventListener('click', () => {
               const name = btn.getAttribute('data-tab');
               setActiveTab(name);
             });
           });
           setActiveTab('overview');
         }
         function formatOverviewStatus(version, debug, headers) {
           const versionText = version?.data?.version || 'unknown';
           const debugData = debug?.data || {};
           const debugEnabled = !!debugData.enabled;
           const ttlRemaining = Number(debugData.ttl_remaining_seconds || 0);
           const maxTtl = Number(debugData.max_ttl_seconds || 0);
           const enrichedHeaders = Array.isArray(headers?.enriched_headers)
             ? headers.enriched_headers
             : (Array.isArray(headers?.data?.enriched_headers) ? headers.data.enriched_headers : []);
           const lines = [
             'Build Version',
             '  - ' + versionText,
             'Debug',
             '  - enabled: ' + (debugEnabled ? 'yes' : 'no'),
             '  - ttl_remaining_seconds: ' + ttlRemaining,
             '  - max_ttl_seconds: ' + maxTtl,
             'Enrichments',
             '  - ' + (enrichedHeaders.length ? enrichedHeaders.join(', ') : '(none)'),
           ];
           return lines.join('\\n');
         }
         async function refreshOverview() {
           try {
             const [version, debug, headers, configYaml] = await Promise.all([
               apiCall(ADMIN_ROOT + '/version', 'GET'),
               apiCall(ADMIN_ROOT + '/debug', 'GET'),
               apiCall(ADMIN_ROOT + '/headers', 'GET'),
               apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true),
             ]);
             setOutput('overview-config-output', configYaml);
             setOutput('overview-output', formatOverviewStatus(version, debug, headers));
           } catch (e) {
             setOutput('overview-config-output', '');
             setOutput('overview-output', String(e.message || e));
           }
         }
         async function debugRefresh() {
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug', 'GET')); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
         async function debugEnable() {
           const ttl = Number(el('ttl-seconds')?.value || 0);
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug', 'PUT', { enabled: true, ttl_seconds: ttl })); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
         async function debugDisable() {
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug', 'DELETE')); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
         async function debugLoadTrace() {
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug/last', 'GET', undefined, true)); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
         async function loggingSave() {
           try {
             const payload = {
               loggingEndpoint: {
                 url: el('logging-url')?.value?.trim() || null,
                 auth_header: el('logging-auth-header')?.value?.trim() || null,
                 auth_value: el('logging-auth-value')?.value || null,
               },
             };
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug/loggingEndpoint', 'PUT', payload));
           } catch (e) {
             setOutput('logging-output', String(e.message || e));
           }
         }
         async function loggingDelete() {
           try { setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug/loggingEndpoint', 'DELETE')); }
           catch (e) { setOutput('logging-output', String(e.message || e)); }
         }
         async function configLoad() {
           try {
             const text = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
             if (el('config-yaml')) el('config-yaml').value = text;
             setConfigValidationError('');
             setOutput('config-output', 'Config reloaded from proxy.');
           } catch (e) {
              setOutput('config-output', String(e.message || e));
           }
         }
         async function configValidate(showOutput) {
           const yaml = el('config-yaml')?.value || '';
           try {
             const res = await fetch(ADMIN_ROOT + '/config/validate', {
               method: 'POST',
               headers: { 'X-Admin-Key': currentKey, 'Content-Type': 'text/yaml' },
               body: yaml,
             });
             if (res.status === 401) {
               handleUnauthorized();
               throw new Error('Unauthorized (401)');
             }
             const text = await res.text();
             let payload = null;
             try {
               payload = JSON.parse(text);
             } catch {
               payload = null;
             }
             if (!res.ok) {
               const errText = extractApiErrorText(payload, text || 'Config validation failed');
               setConfigValidationError(errText);
               if (showOutput) setOutput('config-output', 'Validation failed\\n\\n' + errText);
               return false;
             }
             setConfigValidationError('');
             if (showOutput) setOutput('config-output', formatConfigSummary('Validation successful', payload));
             return true;
           } catch (e) {
             const errText = String(e.message || e);
             setConfigValidationError(errText);
             if (showOutput) setOutput('config-output', 'Validation failed\\n\\n' + errText);
             return false;
           }
         }
         async function configSave() {
           const yaml = el('config-yaml')?.value || '';
           const valid = await configValidate(false);
           if (!valid) {
             setOutput('config-output', 'Save blocked: fix config validation errors first.');
             return;
           }
           try {
             const res = await fetch(ADMIN_ROOT + '/config', {
               method: 'PUT',
               headers: { 'X-Admin-Key': currentKey, 'Content-Type': 'text/yaml' },
               body: yaml,
             });
             if (res.status === 401) {
               handleUnauthorized();
               throw new Error('Unauthorized (401)');
             }
             const text = await res.text();
             try {
               setOutput('config-output', formatConfigSummary('Config saved', JSON.parse(text)));
             } catch {
               setOutput('config-output', text);
             }
           } catch (e) {
             setOutput('config-output', String(e.message || e));
           }
         }
         async function configTestRule() {
           const raw = el('config-test-rule-input')?.value || '';
           let parsed;
           try {
             parsed = raw ? JSON.parse(raw) : {};
           } catch {
             setOutput('config-output', 'Test rule input must be valid JSON.');
             return;
           }
           try {
             const result = await apiCall(ADMIN_ROOT + '/config/test-rule', 'POST', parsed);
             setOutput('config-output', formatConfigSummary('Rule test result', result));
           } catch (e) {
             setOutput('config-output', String(e.message || e));
           }
         }
         async function headersList() {
           try { setOutput('headers-output', await apiCall(ADMIN_ROOT + '/headers', 'GET')); }
           catch (e) { setOutput('headers-output', String(e.message || e)); }
         }
         async function headersSave() {
           const name = (el('header-name')?.value || '').trim();
           const value = el('header-value')?.value || '';
           try { setOutput('headers-output', await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(name), 'PUT', { value })); }
           catch (e) { setOutput('headers-output', String(e.message || e)); }
         }
         async function headersDelete() {
           const name = (el('header-name')?.value || '').trim();
           try { setOutput('headers-output', await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(name), 'DELETE')); }
           catch (e) { setOutput('headers-output', String(e.message || e)); }
         }
         async function rotateProxy() {
           try { setOutput('keys-output', await apiCall(ADMIN_ROOT + '/rotate', 'POST')); }
           catch (e) { setOutput('keys-output', String(e.message || e)); }
         }
         async function rotateAdmin() {
           try {
             const out = await apiCall(ADMIN_ROOT + '/rotate-admin', 'POST');
             setOutput('keys-output', out);
             clearSavedKey();
             setCurrentKey('');
             showWarning('Admin key rotated. Re-enter the new admin key from response.');
           } catch (e) {
             setOutput('keys-output', String(e.message || e));
           }
         }

         function bind() {
           attachTabs();
           el('connect-btn')?.addEventListener('click', async () => {
             const key = readKeyInput();
             if (!key) {
               showWarning('Enter an admin key first.');
               return;
             }
             if (saveKeyChecked()) {
               localStorage.setItem(ADMIN_KEY_STORAGE, key);
             } else {
               clearSavedKey();
             }
             setCurrentKey(key);
             try {
               await refreshOverview();
               await debugRefresh();
               await configLoad();
             } catch {
               // no-op
             }
           });
           el('save-key-local')?.addEventListener('change', (evt) => {
             const checked = !!evt?.target?.checked;
             if (!checked) {
               pendingLocalSaveApproval = false;
               clearSavedKey();
               return;
             }
             const key = readKeyInput();
             if (!key) {
               setSaveKeyChecked(false);
               showWarning('Enter an admin key before enabling local save.');
               return;
             }
             pendingLocalSaveApproval = true;
             el('save-key-modal')?.showModal();
           });
           el('save-key-cancel-btn')?.addEventListener('click', () => {
             pendingLocalSaveApproval = false;
             setSaveKeyChecked(false);
             el('save-key-modal')?.close();
           });
           el('save-key-confirm-btn')?.addEventListener('click', () => {
             pendingLocalSaveApproval = false;
             const key = readKeyInput();
             if (key) localStorage.setItem(ADMIN_KEY_STORAGE, key);
             setSaveKeyChecked(!!key);
             updateSavedWarning();
             el('save-key-modal')?.close();
             showWarning('Admin key will be saved locally on connect.');
           });
           el('save-key-modal')?.addEventListener('close', () => {
             if (pendingLocalSaveApproval) {
               setSaveKeyChecked(false);
               pendingLocalSaveApproval = false;
             }
           });
           el('remove-local-key-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             clearSavedKey();
             showWarning('Saved key removed.');
           });
           el('overview-refresh-btn')?.addEventListener('click', refreshOverview);
           el('debug-refresh-btn')?.addEventListener('click', debugRefresh);
           el('debug-enable-btn')?.addEventListener('click', debugEnable);
           el('debug-disable-btn')?.addEventListener('click', debugDisable);
           el('debug-load-trace-btn')?.addEventListener('click', debugLoadTrace);
           el('logging-save-btn')?.addEventListener('click', loggingSave);
           el('logging-delete-btn')?.addEventListener('click', loggingDelete);
           el('config-reload-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configLoad();
           });
           el('config-test-rule-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configTestRule();
           });
           el('config-save-btn')?.addEventListener('click', configSave);
           el('config-yaml')?.addEventListener('blur', () => configValidate(false));
           el('headers-list-btn')?.addEventListener('click', headersList);
           el('headers-save-btn')?.addEventListener('click', headersSave);
           el('headers-delete-btn')?.addEventListener('click', headersDelete);
           el('rotate-proxy-btn')?.addEventListener('click', rotateProxy);
           el('rotate-admin-btn')?.addEventListener('click', rotateAdmin);
           if (el('config-yaml') && !el('config-yaml').value.trim()) {
             el('config-yaml').value = DEFAULT_CONFIG_YAML_TEMPLATE;
           }

           const saved = localStorage.getItem(ADMIN_KEY_STORAGE);
           updateSavedWarning();
           if (saved) {
             setSaveKeyChecked(true);
             if (el('admin-key')) el('admin-key').value = saved;
             setCurrentKey(saved, true);
             refreshOverview();
             debugRefresh();
             configLoad();
           }
         }
         bind();
       </script>`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

async function handleDebugGet(env) {
  const config = await loadConfigV1(env);
  const maxTtlSeconds = Number(config?.debug?.max_ttl_seconds || 3600);
  const enabledUntilMs = await readDebugEnabledUntilMs(env);
  const now = Date.now();
  return jsonResponse(200, {
    ok: true,
    data: {
      enabled: enabledUntilMs > now,
      enabled_until_ms: enabledUntilMs || 0,
      ttl_remaining_seconds: enabledUntilMs > now ? Math.ceil((enabledUntilMs - now) / 1000) : 0,
      max_ttl_seconds: maxTtlSeconds,
    },
    meta: {},
  });
}

async function handleDebugPut(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const enabled = body?.enabled;
  if (typeof enabled !== "boolean") {
    throw new HttpError(400, "INVALID_REQUEST", "enabled is required and must be a boolean", {
      expected: { enabled: true, ttl_seconds: 3600 },
    });
  }

  const config = await loadConfigV1(env);
  const maxTtlSeconds = Number(config?.debug?.max_ttl_seconds || 3600);

  if (!enabled) {
    await env.CONFIG.put(KV_DEBUG_ENABLED_UNTIL_MS, "0");
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: false,
        enabled_until_ms: 0,
        ttl_remaining_seconds: 0,
        max_ttl_seconds: maxTtlSeconds,
      },
      meta: {},
    });
  }

  const ttlSecondsRaw = body?.ttl_seconds === undefined ? maxTtlSeconds : Number(body.ttl_seconds);
  if (!Number.isInteger(ttlSecondsRaw) || ttlSecondsRaw < 1) {
    throw new HttpError(400, "INVALID_REQUEST", "ttl_seconds must be a positive integer", {
      expected: { enabled: true, ttl_seconds: 3600 },
    });
  }
  if (ttlSecondsRaw > maxTtlSeconds) {
    throw new HttpError(400, "INVALID_REQUEST", "ttl_seconds exceeds configured debug.max_ttl_seconds", {
      received: ttlSecondsRaw,
      max_ttl_seconds: maxTtlSeconds,
    });
  }

  const enabledUntilMs = Date.now() + ttlSecondsRaw * 1000;
  await env.CONFIG.put(KV_DEBUG_ENABLED_UNTIL_MS, String(enabledUntilMs));
  return jsonResponse(200, {
    ok: true,
    data: {
      enabled: true,
      enabled_until_ms: enabledUntilMs,
      ttl_remaining_seconds: ttlSecondsRaw,
      max_ttl_seconds: maxTtlSeconds,
    },
    meta: {},
  });
}

async function handleDebugDelete(env) {
  await env.CONFIG.put(KV_DEBUG_ENABLED_UNTIL_MS, "0");
  const config = await loadConfigV1(env);
  const maxTtlSeconds = Number(config?.debug?.max_ttl_seconds || 3600);
  return jsonResponse(200, {
    ok: true,
    data: {
      enabled: false,
      enabled_until_ms: 0,
      ttl_remaining_seconds: 0,
      max_ttl_seconds: maxTtlSeconds,
    },
    meta: {},
  });
}

async function handleEnrichedHeadersList(env) {
  const names = await listEnrichedHeaderNames(env, getBootstrapEnrichedHeaders(env));
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderPut(request, env, headerNameRaw) {
  enforceInvokeContentType(request);
  const headerName = assertValidHeaderName(headerNameRaw);
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
    throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be changed via API.", {
      header: headerName,
      hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
    });
  }
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = body?.value;
  if (typeof value !== "string" || !value.length) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required and must be a non-empty string", {
      expected: { value: "string" },
    });
  }

  await env.CONFIG.put(enrichedHeaderKvKey(headerName), value);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderDelete(env, headerNameRaw) {
  const headerName = assertValidHeaderName(headerNameRaw);
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
    throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be deleted via API.", {
      header: headerName,
      hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
    });
  }
  const kvKey = enrichedHeaderKvKey(headerName);
  const existing = await env.CONFIG.get(kvKey);
  if (!existing) {
    throw new HttpError(404, "HEADER_NOT_FOUND", "No enriched header exists for the provided name.", {
      name: headerName,
      hint: `List current enriched headers at ${ADMIN_ROOT}/headers.`,
    });
  }
  await env.CONFIG.delete(kvKey);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleInitPage(env, request) {
  ensureKvBinding(env);
  const [existingProxy, existingAdmin] = await Promise.all([env.CONFIG.get(KV_PROXY_KEY), env.CONFIG.get(KV_ADMIN_KEY)]);
  let createdProxy = null;
  let createdAdmin = null;
  const testingDocsUrl = getDocsSectionUrl(env, "testing-out-your-proxy");
  const keyManagementDocsUrl = getDocsSectionUrl(env, "key-management");

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
        "Proxy already initialized. Keys are only shown once.",
        `<p>Instructions to create new keys:</p>
         <p><a href="${escapeHtml(
           keyManagementDocsUrl
         )}" target="_blank" rel="noopener noreferrer">Rotating Keys</a></p>
         <p>Other Instructions</p>
         <p><a href="${escapeHtml(testingDocsUrl)}" target="_blank" rel="noopener noreferrer">Testing out your proxy</a></p>`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return new Response(
    htmlPage(
      "API Transform Proxy",
      `<div style="display:flex;align-items:center;gap:12px;margin:0 0 8px 0;">
         <img src="${FAVICON_DATA_URL}" width="72" height="72" alt="API Transform Proxy icon" />
       </div>
       <div role="alert" style="border:1px solid #fecaca;background:#fff1f2;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin:0 0 12px 0;">
         <div style="font-weight:700;">Save these API keys now</div>
         <div style="font-size:13px;">This is the only time they will be visible. Store them securely before leaving this page.</div>
       </div>
       ${renderSecretField(
         "Admin API Secret (To administer this proxy)",
         createdAdmin || "••••••••••••••••••••••••••••••••",
         "admin-api-secret",
         createdAdmin
           ? "API Key (New). Copy to a safe place. This key cannot be viewed more than once."
           : `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
               keyManagementDocsUrl
             )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         !!createdAdmin
       )}
       ${renderSecretField(
         "Requestor API Secret (To call endpoints through this proxy)",
         createdProxy || "••••••••••••••••••••••••••••••••",
         "requestor-api-secret",
         createdProxy
           ? "API Key (New). Copy to a safe place. This key cannot be viewed more than once."
           : `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
               keyManagementDocsUrl
             )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         !!createdProxy
       )}
       <p><b>How to reset keys</b><br />
       <a href="${escapeHtml(keyManagementDocsUrl)}" target="_blank" rel="noopener noreferrer">Rotating keys</a></p>
       <p><b>How to test</b><br />
       <a href="${escapeHtml(testingDocsUrl)}" target="_blank" rel="noopener noreferrer">Testing out your proxy</a></p>
       ${renderSecretFieldScript()}`
    ),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

function renderSecretField(label, value, id, note = "", actionsEnabled = true) {
  const safeLabel = escapeHtml(label);
  const safeValue = escapeHtml(value);
  const safeId = escapeHtml(id);
  const noteHtml = String(note || "");
  const disabledAttr = actionsEnabled ? "" : " disabled";
  const buttonStyle = actionsEnabled
    ? "padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;cursor:pointer;"
    : "padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;background:#f3f4f6;color:#9ca3af;cursor:not-allowed;opacity:0.85;";
  return `
    <div style="margin:14px 0;">
      <div style="font-weight:700;margin-bottom:6px;">${safeLabel}</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input id="${safeId}" type="password" value="${safeValue}" readonly
          style="flex:1;min-width:320px;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace;" />
        <button type="button" data-toggle-for="${safeId}" onclick="toggleSecret('${safeId}')"
          style="${buttonStyle}"${disabledAttr}>Show</button>
        <button type="button" data-copy-for="${safeId}" onclick="copySecret('${safeId}')"
          style="${buttonStyle}"${disabledAttr}>Copy</button>
      </div>
      ${noteHtml ? `<div style="margin-top:6px;color:#6b7280;font-size:12px;">${noteHtml}</div>` : ""}
    </div>
  `;
}

function renderSecretFieldScript() {
  return `<script>
    function toggleSecret(id) {
      const input = document.getElementById(id);
      const btn = document.querySelector('[data-toggle-for=\"' + id + '\"]');
      if (!input || !btn || btn.disabled) return;
      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      btn.textContent = isHidden ? 'Hide' : 'Show';
    }
    async function copySecret(id) {
      const input = document.getElementById(id);
      const btn = document.querySelector('[data-copy-for=\"' + id + '\"]');
      if (!input || !btn || btn.disabled || !input.value) return;
      try {
        await navigator.clipboard.writeText(input.value);
        const old = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = old; }, 1200);
      } catch {}
    }
  </script>`;
}

function getDocsSectionUrl(env, sectionAnchor) {
  const raw = String(env?.DOCS_URL || DEFAULT_DOCS_URL || "").trim();
  const base = raw ? raw.replace(/#.*$/, "") : DEFAULT_DOCS_URL;
  return `${base}#${sectionAnchor}`;
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

async function handleRootProxyRequest(request, env, ctx) {
  await requireProxyKey(request, env);
  const search = new URL(request.url).search || "";
  const payload = {
    upstream: {
      method: "GET",
      url: `/${search}`,
    },
  };
  return handleRequestCore(request, env, payload, ctx);
}

async function handleRequest(request, env, ctx) {
  await requireProxyKey(request, env);
  enforceInvokeContentType(request);

  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const payload = await readJsonWithLimit(request, maxReq);
  const problems = validateInvokePayload(payload, { allowMissingUrl: true });
  if (problems.length > 0) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid /request payload", {
      expected: EXPECTED_REQUEST_SCHEMA,
      problems,
      received: truncateJsonSnippet(payload),
    });
  }
  return handleRequestCore(request, env, payload, ctx);
}

async function handleRequestCore(request, env, payload, ctx) {
  const maxResp = getEnvInt(env, "MAX_RESP_BYTES", DEFAULTS.MAX_RESP_BYTES);
  const maxExpr = getEnvInt(env, "MAX_EXPR_BYTES", DEFAULTS.MAX_EXPR_BYTES);
  const transformTimeoutMs = getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS);

  const config = await loadConfigV1(env);
  const redactHeaderSet = getDebugRedactHeaderSet(config);
  const debugRequested = String(request.headers.get("X-Proxy-Debug") || "").trim() === "1";
  const debugActive = debugRequested ? await isDebugEnabled(env) : false;
  const debugTrace = debugActive
    ? {
        id: generateSecret().slice(0, 16),
        inbound: {
          timestamp: fmtTs(),
          method: request.method,
          path: new URL(request.url).pathname + new URL(request.url).search,
          headers: toRedactedHeaderMap(request.headers, redactHeaderSet),
          body_preview: previewBodyForDebug(payload),
        },
        outbound: null,
        target_response: null,
        transform: null,
        final_response: null,
      }
    : null;
  const proxyHost = resolveProxyHostForRequest(request, config);
  const headerForwardingPolicy = getHeaderForwardingPolicy(config);

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

  const allowedHosts = getAllowedHosts(env);
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

  if (debugTrace) {
    debugTrace.outbound = {
      timestamp: fmtTs(),
      url: upstreamUrl.toString(),
      method,
      headers: toRedactedHeaderMap(upstreamHeaders, redactHeaderSet),
      body_preview: previewBodyForDebug(upstreamBody || ""),
    };
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
  if (debugTrace) {
    debugTrace.target_response = {
      timestamp: fmtTs(),
      status: upstreamResp.status,
      headers: toRedactedHeaderMap(upstreamResp.headers, redactHeaderSet),
      body_preview: previewBodyForDebug(responseType === "json" ? jsonBody ?? textBody : textBody),
    };
  }

  async function emitDebugTrace(transformInfo, finalHttpStatus, finalBody) {
    if (!debugTrace) return null;
    debugTrace.transform = {
      timestamp: fmtTs(),
      action: transformInfo.action,
      matched_rule: transformInfo.matched_rule || null,
      expression_source: transformInfo.expression_source || "none",
      output_preview: previewBodyForDebug(transformInfo.output_preview || ""),
    };
    debugTrace.final_response = {
      timestamp: fmtTs(),
      http_status: finalHttpStatus,
      body_preview: previewBodyForDebug(finalBody),
    };
    const traceText = buildDebugTraceText(debugTrace);
    lastDebugTrace = {
      id: debugTrace.id,
      timestamp: fmtTs(),
      text: traceText,
    };
    const sink = await pushDebugTraceToLoggingUrl(traceText, debugTrace, config);
    const loggingUrlStatus = !sink.attempted
      ? "off"
      : sink.ok
        ? "ok"
        : `error:${sink.error_code || "LOGGING_URL_ERROR"}${sink.status ? `:${sink.status}` : ""}`;
    const out = {
      "X-Proxy-Debug": "True",
      "X-Proxy-Debug-Trace-Id": debugTrace.id,
      "X-Proxy-Debug-Logging-Endpoint-Status": loggingUrlStatus,
    };
    return out;
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
      const debugHeaders = await emitDebugTrace(
        {
          action: "error",
          matched_rule: null,
          expression_source: "none",
          output_preview: "INVALID_JSON_RESPONSE",
        },
        200,
        { error: { code: "INVALID_JSON_RESPONSE" } }
      );
      return jsonResponse(
        200,
        errorEnvelope("INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase),
        debugHeaders
      );
    }
    const passthroughData = jsonBody !== null ? jsonBody : textBody;
    const debugHeaders = await emitDebugTrace(
      {
        action: "skipped",
        matched_rule: null,
        expression_source: "none",
        output_preview: passthroughData,
      },
      200,
      successEnvelope(passthroughData, metaBase)
    );
    return jsonResponse(200, successEnvelope(passthroughData, metaBase), debugHeaders);
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
      const debugHeaders = await emitDebugTrace(
        {
          action: "error",
          matched_rule: null,
          expression_source: "none",
          output_preview: "INVALID_JSON_RESPONSE",
        },
        200,
        { error: { code: "INVALID_JSON_RESPONSE" } }
      );
      return jsonResponse(
        200,
        errorEnvelope("INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase),
        debugHeaders
      );
    }
    const passthroughData = jsonBody !== null ? jsonBody : textBody;
    const passthroughEnvelope = successEnvelope(passthroughData, {
      ...metaBase,
      skipped: true,
      transform_trace: trace,
    });
    const debugHeaders = await emitDebugTrace(
      {
        action: "skipped",
        matched_rule: null,
        expression_source: "none",
        output_preview: passthroughData,
      },
      200,
      passthroughEnvelope
    );
    return jsonResponse(
      200,
      passthroughEnvelope,
      debugHeaders
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
  const finalEnvelope = successEnvelope(output, {
    ...metaBase,
    parse_ms: parseMs,
    transform_ms: transformMs,
    transform_source: transformSource,
    transform_trace: trace,
  });
  const debugHeaders = await emitDebugTrace(
    {
      action: "executed",
      matched_rule: matchedRule ? matchedRule.name : null,
      expression_source: transformSource,
      output_preview: output,
    },
    200,
    finalEnvelope
  );
  return jsonResponse(200, finalEnvelope, debugHeaders);
}

function htmlPage(title, bodyHtml) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <link rel="icon" type="image/svg+xml" href="${FAVICON_DATA_URL}" />
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 32px; max-width: 820px; }
    p { font-size: 16px; }
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
