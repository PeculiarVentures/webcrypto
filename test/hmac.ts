import { Convert } from "pvtsutils";
import { Crypto } from "../src";
import { ITestGenerateKeyAction, testCrypto } from "./helper";

context("HMAC", () => {

  const crypto = new Crypto();

  testCrypto(crypto, [
    {
      name: "HMAC",
      actions: {
        generateKey: [
          {
            name: "default length",
            algorithm: {
              name: "HMAC",
              hash: "SHA-256",
            } as HmacKeyGenParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
          ...["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
            return {
              name: hash,
              algorithm: {
                name: "HMAC",
                hash,
                length: 128,
              },
              extractable: true,
              keyUsages: ["sign", "verify"],
            } as ITestGenerateKeyAction;
          }),
        ],
        sign: [
          {
            key: {
              format: "raw",
              data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]),
              algorithm: {
                name: "HMAC",
                hash: "SHA-256",
                length: 128,
              } as HmacImportParams,
              extractable: false,
              keyUsages: ["sign", "verify"],
            },
            algorithm: { name: "HMAC" },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromBase64("9yMF9ReX1EhdBWTRjSR+AC21NA05H9W8vx0HZGVmgNc="),
          },
        ],
        import: [
          {
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
            } as HmacImportParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
          {
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
            } as HmacImportParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
          {
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
            } as HmacImportParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
          {
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
            } as HmacImportParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
          {
            name: "raw",
            format: "raw",
            data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
            algorithm: {
              name: "HMAC",
              hash: "SHA-512",
            } as HmacImportParams,
            extractable: true,
            keyUsages: ["sign", "verify"],
          },
        ],
      },
    },
  ]);
});
