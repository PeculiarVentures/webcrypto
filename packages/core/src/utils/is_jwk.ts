import * as types from "@peculiar/webcrypto-types";

export function isJWK(data: unknown): data is types.JsonWebKey {
  return !!(data && typeof data === "object" && "kty" in data);
}

export function assertJWK(data: unknown, paramName: string): asserts data is types.JsonWebKey {
  if (!isJWK(data)) {
    throw new TypeError(`${paramName}: is not JsonWebKey`);
  }
}
