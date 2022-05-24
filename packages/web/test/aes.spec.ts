import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { Browser } from "../src/helper";
import { browser, testCrypto, webCrypto } from "./utils";

context("AES", () => {

  testCrypto(webCrypto, [
    //#region AES-CBC
    {
      name: "AES-128-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 128 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            } as types.AesCbcParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("d5df3ea1598defe7446420802baef28e"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "wrong key size",
            error: true,
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-CBC",
              data: pvtsutils.Convert.FromBase64Url("AQIDBAUGBwgJAAECAwQFBg"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              algorithm: "AES-CBC",
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
            algorithm: {
              name: "AES-CBC",
              iv: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            } as types.AesCbcParams,
            wrappedKey: pvtsutils.Convert.FromHex("c630c4bf95977db13f386cc950b18e98521d54c4fda0ba15b2884d2695638bd9"),
          },
        ],
      },
    },
    {
      name: "AES-192-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 192 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            } as types.AesCbcParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("67d0b3022149829bf009ad4aff19963a"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
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
            algorithm: { name: "AES-CBC", length: 256 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            } as types.AesCbcParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("d827c1c6aee9f0f552c62f30ddee83af"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
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
      // skip: browser.name === Browser.Edge,
      name: "AES-128-CTR",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 128 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              length: 128,
            } as types.AesCtrParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("e1d561c49ce4eb2f448f8a00"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
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
      skip: browser.name === Browser.Chrome // Chrome doesn't implement this alg
        || browser.name === Browser.Edge,
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 192 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              length: 128,
            } as types.AesCtrParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("55a00e2851f00aba53bbd02c"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
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
      skip: browser.name === Browser.Edge,
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CTR", length: 256 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CTR",
              counter: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              length: 128,
            } as types.AesCtrParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("8208d011a20162c8af7a9ce5"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
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
            algorithm: { name: "AES-GCM", length: 128 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: pvtsutils.Convert.FromUtf8String("1234567890ab"),
            } as types.AesGcmParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("68d645649ddf8152a253304d698185072f28cdcf7644ac6064bcb240"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
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
            algorithm: { name: "AES-GCM", length: 192 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: pvtsutils.Convert.FromUtf8String("1234567890ab"),
            } as types.AesGcmParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("d8eab579ed2418f41ca9c4567226f54cb391d3ca2cb6819dace35691"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
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
            algorithm: { name: "AES-GCM", length: 256 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: pvtsutils.Convert.FromUtf8String("1234567890ab"),
            } as types.AesGcmParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("f961f2aadbe689ffce86fcaf2619ab647950afcf19e55b71b857c79d"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
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
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
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
      skip: typeof module !== "undefined", // skip for nodejs
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 128 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            skip: browser.name === Browser.Firefox, // Firefox: Operation is not supported on unwrapKey
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: pvtsutils.Convert.FromHex("000102030405060708090A0B0C0D0E0F"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw",
              data: pvtsutils.Convert.FromHex("00112233445566778899AABBCCDDEEFF"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: pvtsutils.Convert.FromHex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128KW",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
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
      skip: typeof module !== "undefined" // skip for nodejs
        || browser.name === Browser.Chrome, // Chrome doesn't support AES-192-KW
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 192 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            skip: browser.name === Browser.Firefox, // Firefox: Operation is not supported on unwrapKey
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: pvtsutils.Convert.FromHex("000102030405060708090A0B0C0D0E0F1011121314151617"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw",
              data: pvtsutils.Convert.FromHex("00112233445566778899AABBCCDDEEFF0001020304050607"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: pvtsutils.Convert.FromHex("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"),
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
            algorithm: "AES-KW",
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
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
      skip: typeof module !== "undefined", // skip for nodejs
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-KW", length: 256 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            skip: browser.name === Browser.Firefox, // Firefox: Operation is not supported on unwrapKey
            key: {
              format: "raw",
              algorithm: "AES-KW",
              data: pvtsutils.Convert.FromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw",
              data: pvtsutils.Convert.FromHex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"),
              algorithm: "AES-KW",
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            algorithm: {
              name: "AES-KW",
            },
            wrappedKey: pvtsutils.Convert.FromHex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
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

    //#region AES-ECB
    {
      name: "AES-128-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 128 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-ECB",
            } as types.Algorithm,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("c6ec2f91a9f48e10062ae41e86cb299f"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-ECB",
              data: pvtsutils.Convert.FromBase64Url("AQIDBAUGBwgJAAECAwQFBg"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef"),
              algorithm: "AES-ECB",
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
            algorithm: {
              name: "AES-ECB",
            } as types.Algorithm,
            wrappedKey: pvtsutils.Convert.FromHex("039ec14b350bd92efd02dac2c01cdee6ea9953cfbdc067f20f5f47bb4459da79"),
          },
        ],
      },
    },
    {
      name: "AES-192-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 192 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-ECB",
            } as types.Algorithm,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("8c9f297827ad6aaa9e7501e79fb45ca5"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 256 } as types.AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-ECB",
            } as types.Algorithm,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("84ccef71a364b112eb2b3b8b99587a95"),
            key: {
              format: "raw",
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

  ]);

});
