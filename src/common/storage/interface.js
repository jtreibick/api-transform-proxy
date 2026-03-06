export class StorageConnectorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "StorageConnectorError";
    this.code = code;
  }
}

export function createStorageInterface({ keyValue, secrets, durable }) {
  return {
    keyValue,
    secrets,
    durable,
  };
}
