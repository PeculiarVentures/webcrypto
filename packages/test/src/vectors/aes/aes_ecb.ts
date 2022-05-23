import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestParams } from "../../types";

export const AES128ECB: ITestParams = {
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
        data: Convert.FromUtf8String("test message"),
        encData: Convert.FromHex("c6ec2f91a9f48e10062ae41e86cb299f"),
        key: {
          format: "raw",
          data: Convert.FromUtf8String("1234567890abcdef"),
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
        data: Convert.FromUtf8String("1234567890abcdef"),
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
          data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg=="),
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        wKey: {
          format: "raw",
          data: Convert.FromUtf8String("1234567890abcdef"),
          algorithm: "AES-ECB",
          extractable: true,
          keyUsages: ["encrypt", "decrypt"],
        },
        algorithm: {
          name: "AES-ECB",
        } as types.Algorithm,
        wrappedKey: Convert.FromHex("039ec14b350bd92efd02dac2c01cdee6ea9953cfbdc067f20f5f47bb4459da79"),
      },
    ],
  },
};
export const AES192ECB: ITestParams = {
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
        data: Convert.FromUtf8String("test message"),
        encData: Convert.FromHex("8c9f297827ad6aaa9e7501e79fb45ca5"),
        key: {
          format: "raw",
          data: Convert.FromUtf8String("1234567890abcdef12345678"),
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
        data: Convert.FromUtf8String("1234567890abcdef12345678"),
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
};
export const AES256ECB: ITestParams = {
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
        data: Convert.FromUtf8String("test message"),
        encData: Convert.FromHex("84ccef71a364b112eb2b3b8b99587a95"),
        key: {
          format: "raw",
          data: Convert.FromUtf8String("1234567890abcdef1234567809abcdef"),
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
        data: Convert.FromUtf8String("1234567890abcdef1234567890abcdef"),
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
};