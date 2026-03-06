export function createCloudflareDurableStore(env) {
  return {
    kind: "cloudflare.durable",
    getNamespace(bindingName) {
      return env?.[bindingName] || null;
    },
    getStub(bindingName, idName = "default") {
      const ns = env?.[bindingName];
      if (!ns || typeof ns.idFromName !== "function" || typeof ns.get !== "function") return null;
      return ns.get(ns.idFromName(String(idName || "default")));
    },
  };
}
