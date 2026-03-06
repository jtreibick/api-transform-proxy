import { StorageConnectorError } from "../../../common/storage/interface.js";

export function createCloudflareKVStore(env, bindingName = "CONFIG") {
  const binding = env?.[bindingName];

  function assertReady() {
    if (!binding || typeof binding.get !== "function" || typeof binding.put !== "function") {
      throw new StorageConnectorError(
        "MISSING_KV_BINDING",
        `KV binding ${bindingName} is missing or invalid.`
      );
    }
  }

  return {
    kind: "cloudflare.kv",
    bindingName,
    assertReady,
    async get(key, options) {
      assertReady();
      return binding.get(key, options);
    },
    async put(key, value, options) {
      assertReady();
      return binding.put(key, value, options);
    },
    async delete(key) {
      assertReady();
      return binding.delete(key);
    },
    async list(options) {
      assertReady();
      return binding.list(options);
    },
  };
}
