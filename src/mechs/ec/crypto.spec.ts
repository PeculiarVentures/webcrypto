import assert from "node:assert";
import { Buffer } from "node:buffer";
import nodeCrypto from "node:crypto";
import { convert } from "@peculiar/utils";
import * as core from "webcrypto-core";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("EC", () => {
  it("Import wrong named curve", async () => {
    const spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzlbSDQWz+1nwEHsrT516OAEX5YWzwVYj39BH+Rv5yoP9yLgM5wIXgOls5DoLDJVQ+45XDrD/xjSCcul5NACZw==", "base64");
    await assert.rejects(
      crypto.subtle.importKey(
        "spki",
        spki,
        {
          name: "ECDSA",
          namedCurve: "K-256",
        } as Algorithm,
        false,
        ["verify"],
      ),
      core.CryptoError,
    );
  });

  describe("Extra ECC named curves", () => {
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

    describe("sign/verify + pkcs8/spki", () => {
      const data = new Uint8Array(10);

      namedCurves.forEach((namedCurve) => {
        it(namedCurve, async () => {
          const alg: EcKeyGenParams = {
            name: "ECDSA",
            namedCurve,
          };
          const signAlg = {
            ...alg,
            hash: "SHA-256",
          } as EcdsaParams;

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

    describe("deriveBits + jwk", () => {
      namedCurves.forEach((namedCurve) => {
        it(namedCurve, async () => {
          const alg: EcKeyGenParams = {
            name: "ECDH",
            namedCurve,
          };

          const keys = await crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);

          const deriveAlg: EcdhKeyDeriveParams = {
            name: "ECDH",
            public: keys.publicKey,
          };
          const derivedBits = await crypto.subtle.deriveBits(deriveAlg, keys.privateKey, 128);

          const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
          const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
          const privateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
          const publicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, []);

          const derivedBits2 = await crypto.subtle.deriveBits(
            {
              name: "ECDH",
              public: keys.publicKey,
            } as EcdhKeyDeriveParams,
            privateKey,
            128,
          );
          const derivedBits3 = await crypto.subtle.deriveBits(
            {
              name: "ECDH",
              public: publicKey,
            } as EcdhKeyDeriveParams,
            keys.privateKey,
            128,
          );

          assert.strictEqual(convert.encode("hex", derivedBits2), convert.encode("hex", derivedBits));
          assert.strictEqual(convert.encode("hex", derivedBits3), convert.encode("hex", derivedBits));
        });
      });
    });
  });
});

describe("JWK base64url members", () => {
  // EC and RSA members are decoded by webcrypto-core; same results as 1.7.1.
  it.each([
    ["padding", (v: string) => `${v}=`],
    ["base64 alphabet", (v: string) => v.replace(/-/g, "+").replace(/_/g, "/").replace(/^./, "+")],
    ["invalid character", (v: string) => `*${v.slice(1)}`],
  ])("rejects %s in EC 'd' and RSA 'n'", async (_name, change) => {
    const ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
    await assert.rejects(crypto.subtle.importKey("jwk", { ...ec, d: change(ec.d!) }, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]));
    const rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "jwk" });
    await assert.rejects(crypto.subtle.importKey("jwk", { ...rsa, n: change(rsa.n!) }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]));
  });
});
