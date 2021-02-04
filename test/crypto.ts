import assert from "assert";
import { WebcryptoTest } from "@peculiar/webcrypto-test";
import * as core from "webcrypto-core";
import { Crypto } from "../src";

const crypto = new Crypto();

WebcryptoTest.check(crypto as any, {});
context("Crypto", () => {


  context("getRandomValues", () => {

    it("Uint8Array", () => {
      const array = new Uint8Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "0000000000");
      assert.strictEqual(Buffer.from(array2).equals(array), true);
    });

    it("Uint16Array", () => {
      const array = new Uint16Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "00000000000000000000");
      assert.strictEqual(Buffer.from(array2).equals(Buffer.from(array)), true);
    });

  });

  it("Import wrong named curve", async () => {
    const spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzlbSDQWz+1nwEHsrT516OAEX5YWzwVYj39BH+Rv5yoP9yLgM5wIXgOls5DoLDJVQ+45XDrD/xjSCcul5NACZw==", "base64");
    await assert.rejects(crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "K-256" } as Algorithm,
      false,
      ["verify"]), core.CryptoError);
  });

  it("HKDF derive HMAC key", async () => {
    const hkdf = await crypto.subtle.importKey("raw", new Uint8Array([1, 2, 3, 4, 5]), { name: "HKDF" }, false, ["deriveKey"]);
    const hmac = await crypto.subtle.deriveKey({
      name: "HKDF",
      hash: "SHA-256",
      info: new Uint8Array([1, 2, 3, 4, 5]),
      salt: new Uint8Array([1, 2, 3, 4, 5]),
    } as globalThis.HkdfParams,
      hkdf,
      {
        name: "HMAC",
        hash: "SHA-1",
      } as globalThis.HmacImportParams,
      false,
      ["sign"]);
    assert.strictEqual((hmac.algorithm as globalThis.HmacKeyAlgorithm).length, 512);
  });

  context("EdDSA", () => {

    context("generateKey", () => {

      it("Ed25519", async () => {
        const keys = await crypto.subtle.generateKey({ name: "eddsa", namedCurve: "ed25519" } as globalThis.EcKeyGenParams, false, ["sign", "verify"]) as CryptoKeyPair;
        assert.strictEqual(keys.privateKey.algorithm.name, "EdDSA");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "Ed25519");
      });

      it("Ed448", async () => {
        const keys = await crypto.subtle.generateKey({ name: "eddsa", namedCurve: "ed448" } as globalThis.EcKeyGenParams, true, ["sign", "verify"]) as CryptoKeyPair;
        assert.strictEqual(keys.privateKey.algorithm.name, "EdDSA");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "Ed448");

        const data = await crypto.subtle.exportKey("jwk", keys.privateKey);
        assert.strictEqual(data.kty, "OKP");
        assert.strictEqual(data.crv, "Ed448");
        assert.strictEqual(!!data.d, true);
        const privateKey = await crypto.subtle.importKey("jwk", data, { name: "eddsa", namedCurve: "ed448" } as EcKeyImportParams, false, ["sign"]);

        const message = Buffer.from("message");
        const signature = await crypto.subtle.sign({ name: "EdDSA" }, privateKey, message);
        const ok = await crypto.subtle.verify({ name: "EdDSA" }, keys.publicKey, signature, message);
        assert.strictEqual(ok, true);
      });

    });

  });

  context("ECDH-ES", () => {

    context("generateKey", () => {

      it("X25519", async () => {
        const keys = await crypto.subtle.generateKey({ name: "ecdh-es", namedCurve: "x25519" } as globalThis.EcKeyGenParams, false, ["deriveBits", "deriveKey"]) as CryptoKeyPair;
        assert.strictEqual(keys.privateKey.algorithm.name, "ECDH-ES");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "X25519");
      });

      it("X448", async () => {
        const keys = await crypto.subtle.generateKey({ name: "ecdh-es", namedCurve: "x448" } as globalThis.EcKeyGenParams, true, ["deriveBits", "deriveKey"]) as CryptoKeyPair;
        assert.strictEqual(keys.privateKey.algorithm.name, "ECDH-ES");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "X448");

        const bits = await crypto.subtle.deriveBits({ name: "ECDH-ES", public: keys.publicKey } as globalThis.EcdhKeyDeriveParams, keys.privateKey, 256);
        assert.strictEqual(bits.byteLength, 32);

        const data = await crypto.subtle.exportKey("jwk", keys.publicKey);
        assert.strictEqual(data.kty, "OKP");
        assert.strictEqual(data.crv, "X448");
        assert.strictEqual(!!data.x, true);
      });

    });

  });

});
