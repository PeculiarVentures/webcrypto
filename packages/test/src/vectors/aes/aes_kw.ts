import * as types from "@peculiar/webcrypto-types";
import { ITestParams } from "../../types";

export const AES128KW: ITestParams = {
  name: "AES-128-KW",
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
        key: {
          format: "raw",
          algorithm: "AES-KW",
          data: Buffer.from("000102030405060708090A0B0C0D0E0F", "hex"),
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        wKey: {
          format: "raw",
          data: Buffer.from("00112233445566778899AABBCCDDEEFF", "hex"),
          algorithm: "AES-KW",
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        algorithm: {
          name: "AES-KW",
        },
        wrappedKey: Buffer.from("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5", "hex"),
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw",
        data: Buffer.from("1234567890abcdef12345678"),
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
};
export const AES192KW: ITestParams = {
  name: "AES-192-KW",
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
        key: {
          format: "raw",
          algorithm: "AES-KW",
          data: Buffer.from("000102030405060708090A0B0C0D0E0F1011121314151617", "hex"),
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        wKey: {
          format: "raw",
          data: Buffer.from("00112233445566778899AABBCCDDEEFF0001020304050607", "hex"),
          algorithm: "AES-KW",
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        algorithm: {
          name: "AES-KW",
        },
        wrappedKey: Buffer.from("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2", "hex"),
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw",
        data: Buffer.from("1234567890abcdef12345678"),
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
};
export const AES256KW: ITestParams = {
  name: "AES-256-KW",
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
        key: {
          format: "raw",
          algorithm: "AES-KW",
          data: Buffer.from("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "hex"),
          extractable: true,
          keyUsages: ["wrapKey", "unwrapKey"],
        },
        wKey: {
          format: "raw",
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
};