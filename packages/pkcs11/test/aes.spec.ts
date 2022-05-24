import * as assert from "assert";
import { AesCryptoKey } from "../src/mechs";
import { Pkcs11AesKeyGenParams, Pkcs11AesKeyImportParams } from "../src/types";
import { crypto } from "./config";

context("AES", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11AesKeyGenParams = {
        name: "AES-CBC",
        length: 128,
        label: "custom",
        token: true,
        sensitive: true,
      };

      const key = await crypto.subtle.generateKey(alg, false, ["encrypt", "decrypt"]) as AesCryptoKey;

      assert.strictEqual(key.algorithm.token, true);
      assert.strictEqual(key.algorithm.label, alg.label);
      assert.strictEqual(key.algorithm.sensitive, true);
    });

    it("import", async () => {
      const alg: Pkcs11AesKeyImportParams = {
        name: "AES-CBC",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const raw = Buffer.from("1234567890abcdef1234567809abcdef");

      const key = await crypto.subtle.importKey("raw", raw, alg, false, ["encrypt", "decrypt"]) as AesCryptoKey;

      assert.strictEqual(key.algorithm.token, true);
      assert.strictEqual(key.algorithm.label, alg.label);
      assert.strictEqual(key.algorithm.sensitive, true);
    });

  });

});
