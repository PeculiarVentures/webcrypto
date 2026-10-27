import assert from "node:assert";
import { Buffer } from "node:buffer";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("X25519", () => {
  const privateKeyJwk = {
    key_ops: ["deriveBits", "deriveKey"],
    ext: true,
    crv: "X25519",
    d: "AGHXWdGVQi8Is-A4uXYbfpTfDFwxGmJgCLFRHUjb0kM",
    x: "BLsolmWGd1aTexAd_O7MQnL9MpRPVKFO7t9k5Ri04lI",
    kty: "OKP",
  };

  const publicKeyJwk = {
    key_ops: [],
    ext: true,
    crv: "X25519",
    x: "BLsolmWGd1aTexAd_O7MQnL9MpRPVKFO7t9k5Ri04lI",
    kty: "OKP",
  };

  const derivedBitsBase64 = "lWSsBfIyBlat6Q4vHS/MmKXN0Wraz7F82D8prcSRlHw=";

  describe("generateKey", () => {
    it("should generate key pair", async () => {
      const alg = { name: "x25519" };
      const keys = await crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);
      assert.ok("privateKey" in keys);
      assert.ok("publicKey" in keys);
      assert.strictEqual(keys.privateKey.algorithm.name, "X25519");
      assert.strictEqual(keys.privateKey.type, "private");
      assert.strictEqual(keys.privateKey.extractable, true);
      assert.deepStrictEqual(keys.privateKey.usages, ["deriveBits", "deriveKey"]);
      assert.strictEqual(keys.publicKey.algorithm.name, "X25519");
      assert.strictEqual(keys.publicKey.type, "public");
      assert.strictEqual(keys.publicKey.extractable, true);
      assert.deepStrictEqual(keys.publicKey.usages, []);
    });
  });

  describe("import/export", () => {
    it("should correctly import and export private key", async () => {
      const alg = { name: "x25519" };
      const importedPrivateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, alg, true, ["deriveBits", "deriveKey"]);
      const exportedPrivateKeyJwk = await crypto.subtle.exportKey("jwk", importedPrivateKey);
      assert.deepStrictEqual(exportedPrivateKeyJwk, privateKeyJwk);
    });

    it("should correctly import and export public key", async () => {
      const alg = { name: "x25519" };
      const importedPublicKey = await crypto.subtle.importKey("jwk", publicKeyJwk, alg, true, []);
      const exportedPublicKeyJwk = await crypto.subtle.exportKey("jwk", importedPublicKey);
      assert.deepStrictEqual(exportedPublicKeyJwk, publicKeyJwk);
    });
  });

  describe("deriveBits", () => {
    it("should derive bits", async () => {
      const alg = { name: "x25519" };
      const importedPrivateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, alg, false, ["deriveBits"]);
      const importedPublicKey = await crypto.subtle.importKey("jwk", publicKeyJwk, alg, true, []);
      const bits = await crypto.subtle.deriveBits(
        {
          name: "x25519",
          public: importedPublicKey,
        } as EcdhKeyDeriveParams,
        importedPrivateKey,
        256,
      );
      assert.strictEqual(Buffer.from(bits).toString("base64"), derivedBitsBase64);
    });
  });
});
