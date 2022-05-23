import * as types from "@peculiar/webcrypto-types";
import { ITestParams } from "../../types";

export const AES128CTR: ITestParams = {
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
          counter: Buffer.from("1234567890abcdef"),
          length: 128,
        } as types.AesCtrParams,
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
  }
};

export const AES192CTR: ITestParams = {
  name: "AES-192-CTR",
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
          counter: Buffer.from("1234567890abcdef"),
          length: 128,
        } as types.AesCtrParams,
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
  }
};

export const AES256CTR: ITestParams = {
  name: "AES-256-CTR",
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
          counter: Buffer.from("1234567890abcdef"),
          length: 128,
        } as types.AesCtrParams,
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
  }
};