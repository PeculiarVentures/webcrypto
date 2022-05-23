import * as types from "@peculiar/webcrypto-types";

export function isJWK(data: any): data is types.JsonWebKey {
  return typeof data === "object" && "kty" in data;
}
