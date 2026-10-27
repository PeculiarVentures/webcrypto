import assert from "node:assert";
import { Buffer } from "node:buffer";
import { beforeAll, describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("Ed25519", () => {
  describe("generateKey", () => {
    it("should generate key pair", async () => {
      const alg = { name: "ed25519" };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      assert.ok("privateKey" in keys);
      assert.ok("publicKey" in keys);
      assert.strictEqual(keys.privateKey.algorithm.name, "Ed25519");
      assert.strictEqual(keys.privateKey.type, "private");
      assert.strictEqual(keys.privateKey.extractable, false);
      assert.deepStrictEqual(keys.privateKey.usages, ["sign"]);
      assert.strictEqual(keys.publicKey.algorithm.name, "Ed25519");
      assert.strictEqual(keys.publicKey.type, "public");
      assert.strictEqual(keys.publicKey.extractable, true);
      assert.deepStrictEqual(keys.publicKey.usages, ["verify"]);
    });
  });
  describe("sign/verify", () => {
    it("should sign and verify data", async () => {
      const alg = { name: "ed25519" };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      assert.ok("privateKey" in keys);
      const data = Buffer.from("message");
      const signature = await crypto.subtle.sign(alg, keys.privateKey, data);
      assert.ok(signature instanceof ArrayBuffer);
      assert.strictEqual(signature.byteLength, 64);
      const ok = await crypto.subtle.verify(alg, keys.publicKey, signature, data);
      assert.ok(ok);
    });
  });
  describe("import/export", () => {
    let keys: CryptoKeyPair;
    beforeAll(async () => {
      const alg = { name: "ed25519" };
      keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    });
    describe("private key", () => {
      it("JWK", async () => {
        const jwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
        // {
        //   key_ops: [ 'sign' ],
        //   ext: true,
        //   crv: 'Ed25519',
        //   d: 'zAe58NtXQO0A_nNc7REZroi3CARzn31jFr80RSjcrwI',
        //   x: 'xONSvzKNx83TPrwuqLF6TxhlHR8aIfnVhbSAsJ2M-VI',
        //   kty: 'OKP'
        // }
        assert.strictEqual(jwk.kty, "OKP");
        assert.strictEqual(jwk.crv, "Ed25519");
        assert.ok(jwk.d);
        assert.ok(jwk.x);
        assert.strictEqual(jwk.key_ops?.length, 1);
        assert.strictEqual(jwk.key_ops![0], "sign");
        assert.strictEqual(jwk.ext, true);
        assert.strictEqual(Buffer.from(jwk.d, "base64url").byteLength, 32);
        assert.strictEqual(Buffer.from(jwk.x, "base64url").byteLength, 32);

        const alg = { name: "ed25519" };
        const key = await crypto.subtle.importKey("jwk", jwk, alg, false, ["sign"]);
        assert.strictEqual(key.type, "private");
        assert.strictEqual(key.extractable, false);
        assert.deepStrictEqual(key.usages, ["sign"]);
        assert.strictEqual(key.algorithm.name, "Ed25519");
      });
      it("PKCS8", async () => {
        const alg = "ed25519";
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
        const key = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
        assert.strictEqual(key.type, "private");
        assert.strictEqual(key.extractable, false);
        assert.deepStrictEqual(key.usages, ["sign"]);
        assert.strictEqual(key.algorithm.name, "Ed25519");
      });
    });
    describe("public key", () => {
      it("JWK", async () => {
        const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
        assert.strictEqual(jwk.kty, "OKP");
        assert.strictEqual(jwk.crv, "Ed25519");
        assert.ok(jwk.x);
        assert.strictEqual(jwk.key_ops?.length, 1);
        assert.strictEqual(jwk.key_ops![0], "verify");
        assert.strictEqual(jwk.ext, true);

        const alg = { name: "ed25519" };
        const key = await crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"]);
        assert.strictEqual(key.type, "public");
        assert.strictEqual(key.extractable, true);
        assert.deepStrictEqual(key.usages, ["verify"]);
        assert.strictEqual(key.algorithm.name, "Ed25519");
      });
      it("SPKI", async () => {
        const alg = "ed25519";
        const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
        const key = await crypto.subtle.importKey("spki", spki, alg, true, ["verify"]);
        assert.strictEqual(key.type, "public");
        assert.strictEqual(key.extractable, true);
        assert.deepStrictEqual(key.usages, ["verify"]);
        assert.strictEqual(key.algorithm.name, "Ed25519");
      });
      it("RAW", async () => {
        const alg = "ed25519";
        const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
        const key = await crypto.subtle.importKey("raw", raw, alg, true, ["verify"]);
        assert.strictEqual(key.type, "public");
        assert.strictEqual(key.extractable, true);
        assert.deepStrictEqual(key.usages, ["verify"]);
        assert.strictEqual(key.algorithm.name, "Ed25519");
      });
    });
  });
  describe("Vector data", () => {
    const privateKeyJwk = {
      key_ops: ["sign"],
      ext: true,
      crv: "Ed25519",
      d: "EOxUciT6spODKVW-JQXGcIN59oqLvkZU52g8i8bR7Wo",
      x: "Wn9sXjjBJX1BH0A_lVbR_nY8kITs06nkxFl9ZE9XgSg",
      kty: "OKP",
    };

    const publicKeyJwk = {
      key_ops: ["verify"],
      ext: true,
      crv: "Ed25519",
      x: "Wn9sXjjBJX1BH0A_lVbR_nY8kITs06nkxFl9ZE9XgSg",
      kty: "OKP",
    };

    describe("import/export", () => {
      it("should correctly import and export private key", async () => {
        const alg = { name: "ed25519" };
        const importedPrivateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, alg, true, ["sign"]);
        const exportedPrivateKeyJwk = await crypto.subtle.exportKey("jwk", importedPrivateKey);
        assert.deepStrictEqual(exportedPrivateKeyJwk, privateKeyJwk);
      });

      it("should correctly import and export public key", async () => {
        const alg = { name: "ed25519" };
        const importedPublicKey = await crypto.subtle.importKey("jwk", publicKeyJwk, alg, true, ["verify"]);
        const exportedPublicKeyJwk = await crypto.subtle.exportKey("jwk", importedPublicKey);
        assert.deepStrictEqual(exportedPublicKeyJwk, publicKeyJwk);
      });
    });

    describe("sign/verify", () => {
      it("should sign and verify data", async () => {
        const alg = { name: "ed25519" };
        const importedPrivateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, alg, false, ["sign"]);
        const importedPublicKey = await crypto.subtle.importKey("jwk", publicKeyJwk, alg, true, ["verify"]);
        const data = Buffer.from("message");
        const signature = await crypto.subtle.sign(alg, importedPrivateKey, data);
        const ok = await crypto.subtle.verify(alg, importedPublicKey, signature, data);
        assert.ok(ok);
      });
    });
  });
});
