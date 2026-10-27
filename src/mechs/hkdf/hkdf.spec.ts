import assert from "node:assert";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("HKDF", () => {
  it("HKDF derive HMAC key", async () => {
    const hkdf = await crypto.subtle.importKey("raw", new Uint8Array([1, 2, 3, 4, 5]), { name: "HKDF" }, false, ["deriveKey"]);
    const hmac = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        info: new Uint8Array([1, 2, 3, 4, 5]),
        salt: new Uint8Array([1, 2, 3, 4, 5]),
      } as HkdfParams,
      hkdf,
      {
        name: "HMAC",
        hash: "SHA-1",
      } as globalThis.HmacImportParams,
      false,
      ["sign"],
    );
    assert.strictEqual((hmac.algorithm as globalThis.HmacKeyAlgorithm).length, 512);
  });
});
