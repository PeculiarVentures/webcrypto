import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { CryptoKey } from "../src";
import { Pkcs11RsaHashedKeyAlgorithm, Pkcs11EcKeyAlgorithm } from "../src/types";
import { crypto } from "./config";
import { isNSS } from "./helper";

(isNSS("KeyStorage. NSS is readonly")
  ? context.skip
  : context)
  ("KeyStorage", () => {

    beforeEach(async () => {
      let keys = await crypto.keyStorage.keys();
      if (keys.length) {
        await crypto.keyStorage.clear();
      }
      keys = await crypto.keyStorage.keys();
      assert.strictEqual(keys.length, 0);
    });

    context("indexOf", () => {
      ["privateKey", "publicKey"].forEach((type) => {
        it(type, async () => {
          const algorithm: types.RsaHashedKeyGenParams = {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 1024,
          };
          const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
          const key = (keys as any)[type] as CryptoKey;

          const index = await crypto.keyStorage.setItem(key);
          const found = await crypto.keyStorage.indexOf(key);
          assert.strictEqual(found, null);

          const keyByIndex = await crypto.keyStorage.getItem(index);
          assert.strictEqual(keyByIndex.key.id.toString("hex"), key.key.id.toString("hex"));
        });
      });
    });

    context("set/get item", () => {

      it("secret key", async () => {
        let indexes = await crypto.keyStorage.keys();
        assert.strictEqual(indexes.length, 0);
        const algorithm: types.AesKeyGenParams = {
          name: "AES-CBC",
          length: 256,
        };
        const key = await crypto.subtle.generateKey(algorithm, true, ["encrypt", "decrypt"]) as CryptoKey;
        assert.strictEqual(!!key, true, "Has no key value");

        assert.strictEqual(key.algorithm.token, false);
        assert.strictEqual(key.algorithm.label, "AES-256");
        assert.strictEqual(key.algorithm.sensitive, false);

        // Set key
        const index = await crypto.keyStorage.setItem(key);

        // Check indexes amount
        indexes = await crypto.keyStorage.keys();
        assert.strictEqual(indexes.length, 1, "Wrong amount of indexes in storage");
        assert.strictEqual(indexes[0], index, "Wrong index of item in storage");

        // Get key
        const aesKey = await crypto.keyStorage.getItem(index);
        assert.strictEqual(!!aesKey, true);
        assert.strictEqual(aesKey.key.id.toString("hex"), key.key.id.toString("hex"));
        assert.strictEqual(aesKey.algorithm.token, true);
        assert.strictEqual(aesKey.algorithm.label, "AES-256");
        assert.strictEqual(aesKey.algorithm.sensitive, false);
      });

      it("public/private keys", async () => {
        const indexes = await crypto.keyStorage.keys();
        assert.strictEqual(indexes.length, 0);
        const algorithm: types.RsaHashedKeyGenParams = {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 2048,
        };
        const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
        assert(keys, "Has no keys");
        assert(keys.privateKey, "Has no private key");
        assert(keys.publicKey, "Has no public key");
        assert.strictEqual(keys.privateKey.extractable, false);
        assert.strictEqual(keys.publicKey.extractable, true);

        // Set keys
        const privateKeyIndex = await crypto.keyStorage.setItem(keys.privateKey);
        const publicKeyIndex = await crypto.keyStorage.setItem(keys.publicKey);

        // Get keys
        const privateKey = await crypto.keyStorage.getItem(privateKeyIndex);
        assert(privateKey);
        assert.strictEqual(privateKey.extractable, false);

        const publicKey = await crypto.keyStorage.getItem(publicKeyIndex);
        assert(publicKey);
        assert.strictEqual(publicKey.extractable, true);
      });
    });

    it("remove item", async () => {
      const algorithm: types.RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      };
      const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);

      // Set keys to storage
      await crypto.keyStorage.setItem(keys.publicKey);
      await crypto.keyStorage.setItem(keys.privateKey);

      // Check indexes amount
      let indexes = await crypto.keyStorage.keys();
      assert.strictEqual(indexes.length, 2);

      // Remove first item
      await crypto.keyStorage.removeItem(indexes[0]);

      // Check indexes amount
      indexes = await crypto.keyStorage.keys();
      assert.strictEqual(indexes.length, 1);
    });

    context("getItem", () => {

      it("wrong key identity", async () => {
        const key = await crypto.keyStorage.getItem("key not exist");
        assert.strictEqual(key, null);
      });

      context("with algorithm", () => {
        it("RSASSA-PKCS1-v1_5", async () => {
          const algorithm: types.RsaHashedKeyGenParams = {
            name: "RSA-PSS",
            hash: "SHA-1",
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          };
          const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify", "encrypt", "decrypt"]);

          // Set key to storage
          const index = await crypto.keyStorage.setItem(keys.publicKey);

          // Check indexes
          const indexes = await crypto.keyStorage.keys();
          assert.strictEqual(indexes.length, 1);

          // Get key from storage with default algorithm
          const keyDefault = await crypto.keyStorage.getItem(index);
          assert.strictEqual(keyDefault.algorithm.name, "RSASSA-PKCS1-v1_5");
          assert.strictEqual((keyDefault.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-256");
          assert.deepStrictEqual(keyDefault.usages, ["encrypt", "verify"]);

          // Get key from storage and set algorithm
          const key = await crypto.keyStorage.getItem(
            index,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" } as types.RsaHashedImportParams,
            false,
            ["verify"],
          );
          assert.strictEqual(key.algorithm.name, "RSASSA-PKCS1-v1_5");
          assert.strictEqual((key.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-512");
          assert.strictEqual(key.extractable, false);
          assert.deepStrictEqual(key.usages, ["verify"]);
        });

        context("with default algorithm", () => {

          it("RSASSA-PKCS1-v1_5", async () => {
            const keys = await crypto.subtle.generateKey(
              {
                name: "RSA-PSS",
                hash: "SHA-1",
                publicExponent: new Uint8Array([1, 0, 1]),
                modulusLength: 2048,
              } as types.RsaHashedKeyGenParams,
              false,
              ["sign", "verify"],
            );

            // Set key to storage
            const index = await crypto.keyStorage.setItem(keys.publicKey);

            // Check indexes
            const indexes = await crypto.keyStorage.keys();
            assert.strictEqual(indexes.length, 1);

            // Get key from storage with default alg
            const key = await crypto.keyStorage.getItem(index);

            assert.strictEqual(key.algorithm.name, "RSASSA-PKCS1-v1_5");
            assert.strictEqual((key.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-256");
            assert.strictEqual(key.usages.join(","), "verify");
          });

          it("ECDSA P-256", async () => {
            const keys = await crypto.subtle.generateKey(
              {
                name: "ECDSA",
                namedCurve: "P-256",
              } as types.EcKeyGenParams,
              false,
              ["sign", "verify"],
            );

            // Set key to storage
            const index = await crypto.keyStorage.setItem(keys.publicKey);

            // Check indexes
            const indexes = await crypto.keyStorage.keys();
            assert.strictEqual(indexes.length, 1);

            // Get key from storage with default alg
            const key = await crypto.keyStorage.getItem(index);
            assert.strictEqual(key.algorithm.name, "ECDSA");
            assert.strictEqual((key.algorithm as Pkcs11EcKeyAlgorithm).namedCurve, "P-256");
            assert.strictEqual(key.usages.join(","), "verify");
          });

          it("ECDSA P-521", async () => {
            const keys = await crypto.subtle.generateKey({
              name: "ECDSA",
              namedCurve: "P-521",
            } as types.EcKeyGenParams,
              false,
              ["sign", "verify"],
            );

            // Set key to storage
            const index = await crypto.keyStorage.setItem(keys.publicKey);

            // Check indexes
            const indexes = await crypto.keyStorage.keys();
            assert.strictEqual(indexes.length, 1);

            // Get key from storage with default alg
            const key = await crypto.keyStorage.getItem(index);
            assert.strictEqual(key.algorithm.name, "ECDSA");
            assert.strictEqual((key.algorithm as Pkcs11EcKeyAlgorithm).namedCurve, "P-521");
            assert.strictEqual(key.usages.join(","), "verify");
          });

          it("RSA-OAEP", async () => {
            const keys = await crypto.subtle.generateKey({
              name: "RSA-OAEP",
              hash: "SHA-1",
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 2048,
            } as types.RsaHashedKeyGenParams,
              false,
              ["encrypt", "decrypt"],
            );

            // Set key to storage
            const index = await crypto.keyStorage.setItem(keys.publicKey);

            // Check indexes
            const indexes = await crypto.keyStorage.keys();
            assert.strictEqual(indexes.length, 1);

            // Get key from storage we default alg
            const key = await crypto.keyStorage.getItem(index);
            assert.strictEqual(key.algorithm.name, "RSA-OAEP");
            assert.strictEqual((key.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-256");
            assert.strictEqual(key.usages.join(","), "encrypt");

          });

          it("AES-CBC", async () => {
            const aesKey = await crypto.subtle.generateKey({
              name: "AES-CBC",
              length: 256,
            } as types.AesKeyGenParams,
              false,
              ["encrypt", "decrypt"],
            ) as CryptoKey;

            // Set key to storage
            const index = await crypto.keyStorage.setItem(aesKey);

            // Check indexes
            const indexes = await crypto.keyStorage.keys();
            assert.strictEqual(indexes.length, 1);

            // Get key from storage we default alg
            const key = await crypto.keyStorage.getItem(index);
            assert.strictEqual(key.algorithm.name, "AES-CBC");
            assert.strictEqual(key.usages.join(","), "encrypt,decrypt");
          });
        });

        it("ECDH", async () => {
          const keys = await crypto.subtle.generateKey(
            {
              name: "ECDH",
              namedCurve: "P-384",
            } as types.EcKeyGenParams,
            false,
            ["deriveBits"],
          );
          // Set key to storage
          const index = await crypto.keyStorage.setItem(keys.publicKey);

          // Check indexes
          const indexes = await crypto.keyStorage.keys();
          assert.strictEqual(indexes.length, 1);

          // Get key from storage we default alg
          const key = await crypto.keyStorage.getItem(index);
          assert.strictEqual(key.algorithm.name, "ECDH");
          assert.strictEqual((key.algorithm as Pkcs11EcKeyAlgorithm).namedCurve, "P-384");
          assert.strictEqual(key.usages.join(","), "");
        });

      });

    });

  });
