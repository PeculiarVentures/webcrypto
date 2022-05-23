import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { Convert } from "pvtsutils";
import { EcCryptoKey } from "../src/mechs";
import { Pkcs11EcKeyGenParams } from "../src/types";
import { crypto } from "./config";

context("EC", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
        label: "custom",
        token: true,
        sensitive: true,
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

      const privateKey = keys.privateKey as EcCryptoKey;
      assert.strictEqual(privateKey.algorithm.token, true);
      assert.strictEqual(privateKey.algorithm.label, alg.label);
      assert.strictEqual(privateKey.algorithm.sensitive, true);

      const publicKey = keys.publicKey as EcCryptoKey;
      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

    it("import", async () => {
      const alg: Pkcs11EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const spki = Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7MvmXG6zXIRe0q6S9IWJxqeiAl++411K6TGJKtAbs32jxVnLvWGR+QElM0CRs/Xgit5g1xGywroh0cN3cJBbA==");

      const publicKey = await crypto.subtle.importKey("spki", spki, alg, false, ["verify"]) as EcCryptoKey;

      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

  });

  context("Extra ECC named curves", () => {
    const namedCurves = [
      "brainpoolP160r1",
      "brainpoolP160t1",
      "brainpoolP192r1",
      "brainpoolP192t1",
      "brainpoolP224r1",
      "brainpoolP224t1",
      "brainpoolP256r1",
      "brainpoolP256t1",
      "brainpoolP320r1",
      "brainpoolP320t1",
      "brainpoolP384r1",
      "brainpoolP384t1",
      "brainpoolP512r1",
      "brainpoolP512t1",
    ];

    context("sign/verify + pkcs8/spki", () => {
      const data = new Uint8Array(10);

      namedCurves.forEach((namedCurve) => {
        it(namedCurve, async () => {
          const alg: types.EcKeyGenParams = { name: "ECDSA", namedCurve };
          const signAlg = { ...alg, hash: "SHA-256" } as types.EcdsaParams;

          const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

          const signature = await crypto.subtle.sign(signAlg, keys.privateKey, data);

          const ok = await crypto.subtle.verify(signAlg, keys.publicKey, signature, data);
          assert.ok(ok);

          const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
          const spki = await crypto.subtle.exportKey("spki", keys.publicKey);

          const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, alg, true, ["sign"]);
          const publicKey = await crypto.subtle.importKey("spki", spki, alg, true, ["verify"]);

          const signature2 = await crypto.subtle.sign(signAlg, privateKey, data);
          const ok2 = await crypto.subtle.verify(signAlg, keys.publicKey, signature2, data);
          assert.ok(ok2);

          const ok3 = await crypto.subtle.verify(signAlg, publicKey, signature, data);
          assert.ok(ok3);
        });
      });
    });

    context("deriveBits + jwk", () => {
      namedCurves.forEach((namedCurve) => {
        const test = [
          // Skip next curves, SoftHSM throws CKR_FUNCTION_FAILED
          "brainpoolP160r1",
          "brainpoolP160t1",
          "brainpoolP192r1",
          "brainpoolP192t1",
          "brainpoolP224r1",
          "brainpoolP224t1",
        ].includes(namedCurve)
          ? it.skip
          : it;
        test(namedCurve, async () => {
          const alg: types.EcKeyGenParams = { name: "ECDH", namedCurve };

          const keys = await crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);

          const deriveAlg: types.EcdhKeyDeriveParams = { name: "ECDH", public: keys.publicKey };
          const derivedBits = await crypto.subtle.deriveBits(deriveAlg, keys.privateKey, 128);

          const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
          const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
          const privateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
          const publicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, []);

          const derivedBits2 = await crypto.subtle.deriveBits({ name: "ECDH", public: keys.publicKey } as types.EcdhKeyDeriveParams, privateKey, 128);
          const derivedBits3 = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey } as types.EcdhKeyDeriveParams, keys.privateKey, 128);

          assert.strictEqual(Convert.ToHex(derivedBits2), Convert.ToHex(derivedBits));
          assert.strictEqual(Convert.ToHex(derivedBits3), Convert.ToHex(derivedBits));
        });
      });
    });
  });

});
