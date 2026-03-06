const ENVELOPE_PREFIX = "enc:v1:";
const ENVELOPE_ALG = "A256GCM";
const IV_BYTES = 12;
const AES_KEY_BYTES = 32;

const keyCache = new WeakMap();

function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function fromBase64(text) {
  const s = atob(String(text || ""));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i += 1) out[i] = s.charCodeAt(i);
  return out;
}

function parseBase64Key(raw) {
  if (!raw) return null;
  try {
    const bytes = fromBase64(raw.trim());
    if (bytes.length === AES_KEY_BYTES) return bytes;
  } catch {
    // ignore, fallback below
  }
  return null;
}

async function importAesKey(env, keyProvider) {
  if (keyCache.has(env)) return keyCache.get(env);
  const raw = await keyProvider();
  const bytes = parseBase64Key(raw);
  if (!bytes) {
    const e = new Error("MASTER_ENCRYPTION_KEY must be base64 for 32 raw bytes (AES-256 key).");
    e.code = "INVALID_MASTER_ENCRYPTION_KEY";
    throw e;
  }
  const key = await crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  keyCache.set(env, key);
  return key;
}

export function createEnvelopeCrypto({ env, keyProvider }) {
  async function encrypt(plainText) {
    const key = await importAesKey(env, keyProvider);
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const data = new TextEncoder().encode(String(plainText ?? ""));
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const payload = {
      alg: ENVELOPE_ALG,
      iv: toBase64(iv),
      ct: toBase64(new Uint8Array(cipherBuf)),
    };
    return ENVELOPE_PREFIX + toBase64(new TextEncoder().encode(JSON.stringify(payload)));
  }

  async function decryptMaybe(storedValue) {
    if (storedValue == null) return null;
    const text = String(storedValue);
    if (!text.startsWith(ENVELOPE_PREFIX)) return text;

    const key = await importAesKey(env, keyProvider);
    const encoded = text.slice(ENVELOPE_PREFIX.length);
    const payloadText = new TextDecoder().decode(fromBase64(encoded));
    const payload = JSON.parse(payloadText);
    if (!payload || payload.alg !== ENVELOPE_ALG || !payload.iv || !payload.ct) {
      const e = new Error("Invalid encrypted payload format.");
      e.code = "INVALID_ENCRYPTED_PAYLOAD";
      throw e;
    }
    const iv = fromBase64(payload.iv);
    const ct = fromBase64(payload.ct);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(plainBuf);
  }

  return {
    encrypt,
    decryptMaybe,
    prefix: ENVELOPE_PREFIX,
  };
}
