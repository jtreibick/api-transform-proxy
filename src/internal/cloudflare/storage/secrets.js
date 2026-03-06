import { StorageConnectorError } from "../../../common/storage/interface.js";

export function createCloudflareSecretsStore(env) {
  return {
    kind: "cloudflare.secrets",
    // Read-only from Worker runtime env vars/secrets.
    async get(key) {
      if (!key) return null;
      const v = env?.[key];
      return v == null ? null : String(v);
    },
    async set() {
      throw new StorageConnectorError(
        "SECRETS_READ_ONLY",
        "Cloudflare runtime secrets are read-only from Worker code. Set via Wrangler/Cloudflare control plane."
      );
    },
    async delete() {
      throw new StorageConnectorError(
        "SECRETS_READ_ONLY",
        "Cloudflare runtime secrets are read-only from Worker code. Delete via Wrangler/Cloudflare control plane."
      );
    },
  };
}
