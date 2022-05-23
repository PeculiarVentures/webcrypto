import * as types from "@peculiar/webcrypto-types";
import { ITestParams } from "../../types";

export const AES128GCM: ITestParams = {
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
          iv: Buffer.from("1234567890ab"),
        } as types.AesGcmParams,
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
  }
};
export const AES192GCM: ITestParams = {
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
          iv: Buffer.from("1234567890ab"),
        } as types.AesGcmParams,
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
  }
};
export const AES256GCM: ITestParams = {
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
          iv: Buffer.from("1234567890ab"),
        } as types.AesGcmParams,
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
  }
};