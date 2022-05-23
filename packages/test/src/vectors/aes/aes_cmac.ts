
import * as types from "@peculiar/webcrypto-types";
import { ITestParams } from "../../types";

export const AES128CMAC: ITestParams = {
  name: "AES-128-CMAC",
  only: true,
  actions: {
    generateKey: [
      {
        algorithm: { name: "AES-CMAC", length: 128 } as types.AesKeyGenParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
    ],
    sign: [
      {
        algorithm: {
          name: "AES-CMAC",
          length: 256,
        } as types.AesCmacParams,
        data: Buffer.from("test message"),
        signature: Buffer.from("98038e3ad7500d11005b6789c6cf9672", "hex"),
        key: {
          format: "raw",
          data: Buffer.from("1234567890abcdef"),
          algorithm: { name: "AES-CMAC" },
          extractable: true,
          keyUsages: ["sign", "verify"],
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw",
        data: Buffer.from("1234567890abcdef"),
        algorithm: "AES-CMAC",
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      {
        name: "jwk",
        format: "jwk",
        data: {
          kty: "oct",
          alg: "A128CMAC",
          k: "MTIzNDU2Nzg5MGFiY2RlZg",
          ext: true,
          key_ops: ["sign", "verify"],
        },
        algorithm: "AES-CMAC",
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
    ],
  }
};

export const AES192CMAC: ITestParams = {
  name: "AES-192-CMAC",
  only: true,
  actions: {
    generateKey: [
      {
        algorithm: { name: "AES-CMAC", length: 192 } as types.AesKeyGenParams,
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
    ],
    sign: [
      {
        algorithm: {
          name: "AES-CMAC",
          length: 192,
        } as types.AesCmacParams,
        data: Buffer.from("test message"),
        signature: Buffer.from("fe5c107cbcafd8a0a47a83c7bf55f1d0", "hex"),
        key: {
          format: "raw",
          data: Buffer.from("1234567890abcdef12345678"),
          algorithm: { name: "AES-CMAC" },
          extractable: true,
          keyUsages: ["sign", "verify"],
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw",
        data: Buffer.from("1234567890abcdef12345678"),
        algorithm: "AES-CMAC",
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
      {
        name: "jwk",
        format: "jwk",
        data: {
          kty: "oct",
          alg: "A192CMAC",
          k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
          ext: true,
          key_ops: ["sign", "verify"],
        },
        algorithm: "AES-CMAC",
        extractable: true,
        keyUsages: ["sign", "verify"],
      },
    ],
  }
};