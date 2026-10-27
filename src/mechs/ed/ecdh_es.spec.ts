import assert from "node:assert";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("ECDH-ES", () => {
  describe("generateKey", () => {
    it("X25519", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "ecdh-es",
          namedCurve: "x25519",
        } as globalThis.EcKeyGenParams,
        false,
        ["deriveBits", "deriveKey"],
      );
      assert.strictEqual(keys.privateKey.algorithm.name, "ECDH-ES");
      assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "X25519");
    });

    it("X448", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "ecdh-es",
          namedCurve: "x448",
        } as globalThis.EcKeyGenParams,
        true,
        ["deriveBits", "deriveKey"],
      );
      assert.strictEqual(keys.privateKey.algorithm.name, "ECDH-ES");
      assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "X448");

      const bits = await crypto.subtle.deriveBits(
        {
          name: "ECDH-ES",
          public: keys.publicKey,
        } as globalThis.EcdhKeyDeriveParams,
        keys.privateKey,
        256,
      );
      assert.strictEqual(bits.byteLength, 32);

      const data = await crypto.subtle.exportKey("jwk", keys.publicKey);
      assert.strictEqual(data.kty, "OKP");
      assert.strictEqual(data.crv, "X448");
      assert.strictEqual(!!data.x, true);
    });
  });
});
