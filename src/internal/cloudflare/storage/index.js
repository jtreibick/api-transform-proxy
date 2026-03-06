import { createStorageInterface } from "../../../common/storage/interface.js";
import { createCloudflareKVStore } from "./kv.js";
import { createCloudflareSecretsStore } from "./secrets.js";
import { createCloudflareDurableStore } from "./durable.js";

const cache = new WeakMap();

export function createCloudflareStorage(env) {
  if (!env || typeof env !== "object") {
    return createStorageInterface({
      keyValue: createCloudflareKVStore(env),
      secrets: createCloudflareSecretsStore(env),
      durable: createCloudflareDurableStore(env),
    });
  }

  if (cache.has(env)) return cache.get(env);

  const storage = createStorageInterface({
    keyValue: createCloudflareKVStore(env, "CONFIG"),
    secrets: createCloudflareSecretsStore(env),
    durable: createCloudflareDurableStore(env),
  });
  cache.set(env, storage);
  return storage;
}
