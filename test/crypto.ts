import assert from "assert";
import process from "process";
import { WebcryptoTest } from "@peculiar/webcrypto-test";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Crypto } from "../src";

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
const nodeMajorVersion = parseInt(/^v(\d+)/.exec(process.version)![1], 10);

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

    it("Uint8Array subarray", () => {
      const array = new Uint8Array(10);
      const subarray = array.subarray(0, 5);
      const array2 = crypto.getRandomValues(subarray);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "00000000000000000000");
      assert.strictEqual(subarray, array2);
      assert.ok(Buffer.from(array).toString("hex").endsWith("0000000000"));
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
    } as HkdfParams,
      hkdf,
      {
        name: "HMAC",
        hash: "SHA-1",
      } as globalThis.HmacImportParams,
      false,
      ["sign"]);
    assert.strictEqual((hmac.algorithm as globalThis.HmacKeyAlgorithm).length, 512);
  });

  (nodeMajorVersion < 14 ? context.skip : context)("EdDSA", () => {

    context("generateKey", () => {

      it("RSA 3072bits", async () => {
        const alg: globalThis.RsaHashedKeyGenParams = {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 3072,
        };
        const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

        assert.strictEqual((keys.privateKey.algorithm as RsaHashedKeyAlgorithm).modulusLength, 3072);
      });

      it("Ed25519", async () => {
        const keys = await crypto.subtle.generateKey({ name: "eddsa", namedCurve: "ed25519" } as globalThis.EcKeyGenParams, false, ["sign", "verify"]);

        assert.strictEqual(keys.privateKey.algorithm.name, "EdDSA");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "Ed25519");
      });

      it("Ed448", async () => {
        const keys = await crypto.subtle.generateKey({ name: "eddsa", namedCurve: "ed448" } as globalThis.EcKeyGenParams, true, ["sign", "verify"]);
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

  (nodeMajorVersion < 14 ? context.skip : context)("ECDH-ES", () => {

    context("generateKey", () => {

      it("X25519", async () => {
        const keys = await crypto.subtle.generateKey({ name: "ecdh-es", namedCurve: "x25519" } as globalThis.EcKeyGenParams, false, ["deriveBits", "deriveKey"]);
        assert.strictEqual(keys.privateKey.algorithm.name, "ECDH-ES");
        assert.strictEqual((keys.privateKey.algorithm as EcKeyAlgorithm).namedCurve, "X25519");
      });

      it("X448", async () => {
        const keys = await crypto.subtle.generateKey({ name: "ecdh-es", namedCurve: "x448" } as globalThis.EcKeyGenParams, true, ["deriveBits", "deriveKey"]);
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
          const alg: EcKeyGenParams = { name: "ECDSA", namedCurve };
          const signAlg = { ...alg, hash: "SHA-256" } as EcdsaParams;

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
        it(namedCurve, async () => {
          const alg: EcKeyGenParams = { name: "ECDH", namedCurve };

          const keys = await crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);

          const deriveAlg: EcdhKeyDeriveParams = { name: "ECDH", public: keys.publicKey };
          const derivedBits = await crypto.subtle.deriveBits(deriveAlg, keys.privateKey, 128);

          const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
          const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
          const privateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
          const publicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, []);

          const derivedBits2 = await crypto.subtle.deriveBits({ name: "ECDH", public: keys.publicKey } as EcdhKeyDeriveParams, privateKey, 128);
          const derivedBits3 = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey } as EcdhKeyDeriveParams, keys.privateKey, 128);

          assert.strictEqual(Convert.ToHex(derivedBits2), Convert.ToHex(derivedBits));
          assert.strictEqual(Convert.ToHex(derivedBits3), Convert.ToHex(derivedBits));
        });
      });
    });
  });

  it("Import Secret JWK without 'alg' and 'key_ops' fields", async () => {
    const aesKey = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
    const jwk = await crypto.subtle.exportKey("jwk", aesKey);
    delete jwk.key_ops;
    delete jwk.alg;
    const hmacKey = await crypto.subtle.importKey("jwk", jwk, { name: "HMAC", hash: "SHA-256" } as Algorithm, false, ["sign", "verify"]);
    assert.strictEqual(hmacKey.algorithm.name, "HMAC");
  });

  context("shake digest", () => {

    const data = Buffer.from("test data");

    context("shake128", () => {

      it("default", async () => {
        const hash = await crypto.subtle.digest("shake128", data);

        assert.strictEqual(Buffer.from(hash).toString("hex"), "ae3bdcf04986a8e7ddd99ac948254693");
      });

      it("128 byte length", async () => {
        const hash = await crypto.subtle.digest({ name: "shake128", length: 128 } as core.ShakeParams, data);

        assert.strictEqual(Buffer.from(hash).toString("hex"), "ae3bdcf04986a8e7ddd99ac948254693fc32ca6ce3ed278c0c54127f072ba21e977d76aa76cab8f85f61c3e1fb7dab42c6b96d39f96fbd8cdcba7121e28cc97bb51f277a00398f99a9e6f11d027473cbffb3ac4ce444e2e8284caeca4e62f725d340fa3519eec7ca3eb4188607c26b0ecdf3750beba8882d6f2b734960cca914");
      });

    });

    context("shake128", () => {

      it("default", async () => {
        const hash = await crypto.subtle.digest("shake256", data);

        assert.strictEqual(Buffer.from(hash).toString("hex"), "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e26");
      });

      it("256 byte length", async () => {
        const hash = await crypto.subtle.digest({ name: "shake256", length: 256 } as core.ShakeParams, data);

        assert.strictEqual(Buffer.from(hash).toString("hex"), "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e262dd68c2a2f932847f9610eeb51f8ba1a180ca878c788e900d899538d45c9c4a6f1bf10d8502a7ccbd9fd540bd856591000700e10130673ef970ffb788afe08426648a216d032733b71e85f128f1ed9e4c8bd910b5000e8c381afb45735680eaf7cb5bf1ae4265ee0822dfe6a9426ff21e309398df57cbf5861f5947f3d261e2d4517ff0d1be988e7014a09c4312d37010cf0e47468c1cf832e6a61e9d9fe3b67e6ab265cb6d95ad7a1f863d71e0e6ed5cd17d568b86e99d84bdb970a580f551017b501ae6761d2d6de76a64385dc10f27d18c2564a6bfbfb1e3f335010bebdf8");
      });

    });

  });

  context("SHA3", () => {
    const data = new Uint8Array(10);
    it("SHA3-256", async () => {
      const digest = await crypto.subtle.digest("SHA3-256", data);
      assert.strictEqual(Convert.ToHex(digest), "0cd5285ba8524fe42ac8f0076de9135d056132a9996213ae1c0f1420c908418b");
    });
    it("SHA3-384", async () => {
      const digest = await crypto.subtle.digest("SHA3-384", data);
      assert.strictEqual(Convert.ToHex(digest), "f54cecb8c160015f87b9e51edd087e10479d60479a42ff7e907ddf129fd7cb2782eb5624c43b453a24cffd8cbe42d0ec");
    });
    it("SHA3-512", async () => {
      const digest = await crypto.subtle.digest("SHA3-512", data);
      assert.strictEqual(Convert.ToHex(digest), "e12f775adfb4e440b74af7b670849a44b7efd1612a97a3a201080cb31944f1f2d9f0eae6b7c0cdb602f6ff0ba181add9997fd06e43f992df577aa52153ca0d27");
    });
  });

  context("ECDH deriveBits with null", () => {
    it("P-256", async () => {
      const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: keyPair.publicKey.algorithm.name, public: keyPair.publicKey } as globalThis.EcdhKeyDeriveParams, keyPair.privateKey, <number><unknown>null);
      assert.equal(bits.byteLength, 32);
    });

    it("P-384", async () => {
      const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: keyPair.publicKey.algorithm.name, public: keyPair.publicKey } as globalThis.EcdhKeyDeriveParams, keyPair.privateKey, <number><unknown>null);
      assert.equal(bits.byteLength, 48);
    });

    it("P-521", async () => {
      const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: keyPair.publicKey.algorithm.name, public: keyPair.publicKey } as globalThis.EcdhKeyDeriveParams, keyPair.privateKey, <number><unknown>null);
      assert.equal(bits.byteLength, 66);
    });
  });
});
