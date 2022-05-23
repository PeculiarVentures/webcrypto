import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { Convert } from "pvtsutils";
import { ITestParams, ITestGenerateKeyAction } from "../types";

export const HMAC: ITestParams = {
  name: "HMAC",
  actions: {
    generateKey: [
      ...["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
        return {
          name: `default length for ${hash} algorithm`,
          algorithm: {
            name: "HMAC",
            hash,
          } as types.HmacKeyGenParams,
          extractable: true,
          keyUsages: ["sign", "verify"],
          assert: (key: types.CryptoKey) => {
            const algorithm = key.algorithm as types.HmacKeyAlgorithm;
            // Chrome, Safari and Firefox return key with algorithm length 512 bits
            assert.equal(algorithm.length, 512);
          },
        } as ITestGenerateKeyAction;
      }),
      ...["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
        return {
          name: `Fixed length:160 for ${hash}`,
          algorithm: {
            name: "HMAC",
            hash,
            length: 160,
          },
          extractable: true,
          keyUsages: ["sign", "verify"],
          assert: (key: types.CryptoKey) => {
            const algorithm = key.algorithm as types.HmacKeyAlgorithm;
            assert.equal(algorithm.length, 160);
          }
        } as ITestGenerateKeyAction;
      }),
      ...["SHA-1"].map((hash) => {
        return {
          name: `Round length 164->160`,
          algorithm: {
            name: "HMAC",
            hash,
            length: 164,
          },
          extractable: true,
          keyUsages: ["sign", "verify"],
          assert: (key: types.CryptoKey) => {
            const algorithm = key.algorithm as types.HmacKeyAlgorithm;
            assert.equal(algorithm.length, 160);
          }
        } as ITestGenerateKeyAction;
      }),
    ],
    sign: [
      {
        name: "HMAC-SHA256 without length param",
        key: {
          format: "raw",
          data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]),
          algorithm: {
            name: "HMAC",
            hash: "SHA-256",
          } as types.HmacImportParams,
          extractable: false,
          keyUsages: ["sign", "verify"],
        },
        algorithm: { name: "HMAC" },
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        signature: Convert.FromHex("ad05febab44cd369e27433bbf00e63e6271f6a350614bec453f5d0efd6503a31"),
      },
    ],
    import: [
      { // JWK SHA-1
        name: "JWK SHA-1",
        format: "jwk",
        data: {
          alg: "HS1",
          ext: true,
          k: "AQIDBAUGBwgJAAECAwQFBg",
          key_ops: ["sign", "verify"],
          kty: "oct",
        },
        algorithm: {
          name: "HMAC",
          hash: "SHA-1",
          length: 128,
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      { // JWK SHA-256
        name: "JWK SHA-256",
        format: "jwk",
        data: {
          alg: "HS256",
          ext: true,
          k: "AQIDBAUGBwgJAAECAwQFBg",
          key_ops: ["sign", "verify"],
          kty: "oct",
        },
        algorithm: {
          name: "HMAC",
          hash: "SHA-256",
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      { // JWK SHA-384
        name: "JWK SHA-384",
        format: "jwk",
        data: {
          alg: "HS384",
          ext: true,
          k: "AQIDBAUGBwgJAAECAwQFBg",
          key_ops: ["sign", "verify"],
          kty: "oct",
        },
        algorithm: {
          name: "HMAC",
          hash: "SHA-384",
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      { // JWK SHA-512
        name: "JWK SHA-512",
        format: "jwk",
        data: {
          alg: "HS512",
          ext: true,
          k: "AQIDBAUGBwgJAAECAwQFBg",
          key_ops: ["sign", "verify"],
          kty: "oct",
        },
        algorithm: {
          name: "HMAC",
          hash: "SHA-512",
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      { // raw 128
        name: "raw 128",
        format: "raw",
        data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg=="),
        algorithm: {
          name: "HMAC",
          hash: "SHA-512",
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      { // raw 160
        name: "raw 160",
        format: "raw",
        data: new Uint8Array(20),
        algorithm: {
          name: "HMAC",
          hash: "SHA-512",
        } as types.HmacImportParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
    ],
  },
};