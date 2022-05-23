import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestParams } from "../../types";

export const AES128CBC: ITestParams = {
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
          iv: Buffer.from("1234567890abcdef"),
        } as types.AesCbcParams,
        data: Buffer.from("test message"),
        encData: Buffer.from("d5df3ea1598defe7446420802baef28e", "hex"),
        key: {
          format: "raw",
          data: Buffer.from("1234567890abcdef"),
          algorithm: { name: "AES-CBC" },
          extractable: true,
          keyUsages: ["encrypt", "decrypt"],
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw" as types.KeyFormat,
        data: Buffer.from("1234567890abcdef"),
        algorithm: "AES-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
      {
        name: "wrong key size",
        error: Error,
        format: "raw" as types.KeyFormat,
        data: Buffer.from("12345678"),
        algorithm: "AES-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
      {
        name: "jwk",
        format: "jwk" as types.KeyFormat,
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
          data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg=="),
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        wKey: {
          format: "raw" as types.KeyFormat,
          data: Buffer.from("1234567890abcdef"),
          algorithm: "AES-CBC",
          extractable: true,
          keyUsages: ["encrypt", "decrypt"],
        },
        algorithm: {
          name: "AES-CBC",
          iv: Buffer.from("1234567890abcdef"),
        } as types.AesCbcParams,
        wrappedKey: Convert.FromHex("c630c4bf95977db13f386cc950b18e98521d54c4fda0ba15b2884d2695638bd9"),
      },
    ],
  }
};

export const AES192CBC: ITestParams = {
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
          iv: Buffer.from("1234567890abcdef"),
        } as types.AesCbcParams,
        data: Buffer.from("test message"),
        encData: Buffer.from("67d0b3022149829bf009ad4aff19963a", "hex"),
        key: {
          format: "raw" as types.KeyFormat,
          data: Buffer.from("1234567890abcdef12345678"),
          algorithm: { name: "AES-CBC" },
          extractable: true,
          keyUsages: ["encrypt", "decrypt"],
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw" as types.KeyFormat,
        data: Buffer.from("1234567890abcdef12345678"),
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
  }
};

export const AES256CBC: ITestParams = {
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
          iv: Buffer.from("1234567890abcdef"),
        } as types.AesCbcParams,
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
  }
};