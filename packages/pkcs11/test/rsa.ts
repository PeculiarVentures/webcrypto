import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { RsaCryptoKey } from "../src/mechs";
import { Pkcs11RsaHashedImportParams, Pkcs11RsaHashedKeyGenParams } from "../src/types";
import { crypto } from "./config";

context("RSA", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
        label: "custom",
        token: true,
        sensitive: true,
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

      const privateKey = keys.privateKey as RsaCryptoKey;
      assert.strictEqual(privateKey.algorithm.token, true);
      assert.strictEqual(privateKey.algorithm.label, alg.label);
      assert.strictEqual(privateKey.algorithm.sensitive, true);

      const publicKey = keys.publicKey as RsaCryptoKey;
      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

    it("import", async () => {
      const alg: Pkcs11RsaHashedImportParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const jwk = {
        alg: "RS256",
        e: "AQAB",
        ext: true,
        key_ops: ["verify"],
        kty: "RSA",
        n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
      };

      const publicKey = await crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"]) as RsaCryptoKey;

      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

  });

  it("RSA 3072bits", async () => {
    const alg: types.RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 3072,
    };
    const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

    assert.strictEqual((keys.privateKey.algorithm as types.RsaHashedKeyAlgorithm).modulusLength, 3072);
  });

});
