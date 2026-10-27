import assert from "node:assert";
import { Buffer } from "node:buffer";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("EdDSA", () => {
  describe("generateKey", () => {
    it("Ed25519", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "eddsa",
          namedCurve: "ed25519",
        } as globalThis.EcKeyGenParams,
        false,
        ["sign", "verify"],
      );

      assert.strictEqual(keys.privateKey.algorithm.name, "EdDSA");
      assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "Ed25519");
    });

    it("Ed448", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "eddsa",
          namedCurve: "ed448",
        } as globalThis.EcKeyGenParams,
        true,
        ["sign", "verify"],
      );
      assert.strictEqual(keys.privateKey.algorithm.name, "EdDSA");
      assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "Ed448");

      const data = await crypto.subtle.exportKey("jwk", keys.privateKey);
      assert.strictEqual(data.kty, "OKP");
      assert.strictEqual(data.crv, "Ed448");
      assert.strictEqual(!!data.d, true);
      const privateKey = await crypto.subtle.importKey(
        "jwk",
        data,
        {
          name: "eddsa",
          namedCurve: "ed448",
        } as EcKeyImportParams,
        false,
        ["sign"],
      );

      const message = Buffer.from("message");
      const signature = await crypto.subtle.sign({ name: "EdDSA" }, privateKey, message);
      const ok = await crypto.subtle.verify({ name: "EdDSA" }, keys.publicKey, signature, message);
      assert.strictEqual(ok, true);
    });
  });
});
