import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import * as graphene from "graphene-pk11";
import { ID_DIGEST } from "../src/const";
import { CryptoKey } from "../src/key";
import { crypto } from "./config";

context("Subtle", () => {

  async function getId(publicKey: types.CryptoKey) {
    const raw = await crypto.subtle.exportKey("spki", publicKey);
    const hash = await (await crypto.subtle.digest(ID_DIGEST, raw)).slice(0, 16);
    return Buffer.from(hash).toString("hex");
  }

  context("key must have id equals to SHA-1 of public key raw", () => {

    context("generate key", () => {

      before(async () => {
        crypto.keyStorage.clear();
      });

      after(async () => {
        crypto.keyStorage.clear();
      });

      [
        { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024 },
        { name: "ECDSA", namedCurve: "P-256" },
      ].map((alg) => {
        it(alg.name, async () => {
          const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

          const id = await getId(keys.publicKey);
          assert.strictEqual((keys.publicKey as CryptoKey).key.id.toString("hex"), id);
          assert.strictEqual((keys.publicKey as CryptoKey).id.includes(id), true);
          assert.strictEqual((keys.publicKey as CryptoKey).p11Object.token, false);
          assert.strictEqual((keys.privateKey as CryptoKey).p11Object.token, false);
          assert.strictEqual(((keys.privateKey as CryptoKey).p11Object as graphene.PrivateKey).sensitive, false);
        });
      });

      context("pkcs11 attributes", () => {
        [
          { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024, token: true, sensitive: true, label: "RSA-PSS" },
          { name: "ECDSA", namedCurve: "P-256", token: true, sensitive: true, label: "ECDSA" },
        ].map((alg) => {
          it(alg.name, async () => {
            const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

            const id = await getId(keys.publicKey);
            assert.strictEqual((keys.publicKey as CryptoKey).key.id.toString("hex"), id);
            assert.strictEqual((keys.publicKey as CryptoKey).id.includes(id), true);
            assert.strictEqual((keys.publicKey as CryptoKey).p11Object.token, true);
            assert.strictEqual((keys.publicKey as CryptoKey).p11Object.label, alg.name);
            assert.strictEqual((keys.privateKey as CryptoKey).p11Object.token, true);
            assert.strictEqual(((keys.privateKey as CryptoKey).p11Object as graphene.PrivateKey).sensitive, true);
            assert.strictEqual((keys.privateKey as CryptoKey).p11Object.label, alg.name);
          });
        });
      });

    });

    context("import key", () => {

      const spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZMMqyfA16N6bvloFHmalk/SGMisr3zSXFZdR8F9UkaY7hF13hHiQtwp2YO+1zd7jwYi1Y7SMA9iUrC+ap2OCw==", "base64");

      it("extractable public key", async () => {
        const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" } as types.EcKeyImportParams, true, ["verify"]);

        const id = await getId(key);
        assert.strictEqual((key as CryptoKey).key.id.toString("hex"), id);
        assert.strictEqual((key as CryptoKey).id.includes(id), true);
      });

      it("don't try to update id if key is not extractable", async () => {
        const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" } as types.EcKeyImportParams, false, ["verify"]);

        assert.notStrictEqual((key as CryptoKey).key.id.toString("hex"), "69e4556056c8d300eff3d4523fc6515d9f833fe6");
      });

    });

  });

});
