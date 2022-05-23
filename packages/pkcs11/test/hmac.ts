import * as assert from "assert";
import { HmacCryptoKey } from "../src/mechs";
import { Pkcs11HmacKeyGenParams, Pkcs11HmacKeyImportParams } from "../src/types";
import { crypto } from "./config";

context("HMAC", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11HmacKeyGenParams = {
        name: "HMAC",
        hash: "SHA-256",
        label: "custom",
        token: true,
        sensitive: true,
      };

      const key = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

      assert.strictEqual(key.algorithm.token, true);
      assert.strictEqual(key.algorithm.label, alg.label);
      assert.strictEqual(key.algorithm.sensitive, true);
    });

    it("import", async () => {
      const alg: Pkcs11HmacKeyImportParams = {
        name: "HMAC",
        hash: "SHA-256",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const raw = Buffer.from("1234567890abcdef1234567809abcdef");

      const key = await crypto.subtle.importKey("raw", raw, alg, false, ["sign", "verify"]) as HmacCryptoKey;

      assert.strictEqual(key.algorithm.token, true);
      assert.strictEqual(key.algorithm.label, alg.label);
      assert.strictEqual(key.algorithm.sensitive, true);
    });

  });

});
