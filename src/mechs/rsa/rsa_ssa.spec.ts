import assert from "node:assert";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("RSASSA-PKCS1-v1_5", () => {
  it("RSA 3072bits", async () => {
    const alg: globalThis.RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 3072,
    };
    const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

    assert.strictEqual((keys.privateKey.algorithm as RsaHashedKeyAlgorithm).modulusLength, 3072);
  }, 5000);
});
