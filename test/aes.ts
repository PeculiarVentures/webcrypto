import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Crypto } from "../src";
import { testCrypto } from "./helper";

context("AES", () => {

  const crypto = new Crypto();

  testCrypto(crypto, [
    //#region AES-CBC
    {
      name: "AES-128-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d5df3ea1598defe7446420802baef28e", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "wrong key size",
            error: core.OperationError,
            format: "raw" as KeyFormat,
            data: Buffer.from("12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk" as KeyFormat,
            data: {
              kty: "oct",
              alg: "A128CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-CBC",
              data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: "AES-CBC",
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            wrappedKey: Convert.FromHex("c630c4bf95977db13f386cc950b18e98521d54c4fda0ba15b2884d2695638bd9"),
          },
        ],
      },
    },
    {
      name: "AES-192-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("67d0b3022149829bf009ad4aff19963a", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d827c1c6aee9f0f552c62f30ddee83af", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

    //#region AES-CTR
    {
      name: "AES-128-CTR",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: Buffer.from("1234567890abcdef"),
              length: 128,
            } as AesCtrParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("e1d561c49ce4eb2f448f8a00", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-CTR" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128CTR",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-192-CTR",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: Buffer.from("1234567890abcdef"),
              length: 128,
            } as AesCtrParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("55a00e2851f00aba53bbd02c", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-CTR" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192CTR",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-CTR",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: Buffer.from("1234567890abcdef"),
              length: 128,
            } as AesCtrParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("8208d011a20162c8af7a9ce5", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-CTR" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256CTR",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CTR",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

    //#region AES-GCM
    {
      name: "AES-128-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-GCM", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("68d645649ddf8152a253304d698185072f28cdcf7644ac6064bcb240", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-192-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-GCM", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d8eab579ed2418f41ca9c4567226f54cb391d3ca2cb6819dace35691", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("f961f2aadbe689ffce86fcaf2619ab647950afcf19e55b71b857c79d", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

    //#region AES-KW
    {
      name: "AES-128-KW",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: Buffer.from("000102030405060708090A0B0C0D0E0F", "hex"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("00112233445566778899AABBCCDDEEFF", "hex"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: Buffer.from("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5", "hex")
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192KW",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["wrapKey", "unwrapKey"],
            },
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-192-KW",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: Buffer.from("000102030405060708090A0B0C0D0E0F1011121314151617", "hex"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("00112233445566778899AABBCCDDEEFF0001020304050607", "hex"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: Buffer.from("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2", "hex")
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192KW",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["wrapKey", "unwrapKey"],
            },
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-KW",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: Buffer.from("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "hex"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "hex"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: Buffer.from("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21", "hex"),
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256KW",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["wrapKey", "unwrapKey"],
            },
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

  ]);

});
