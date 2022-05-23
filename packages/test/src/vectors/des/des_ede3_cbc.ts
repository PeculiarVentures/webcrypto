import { ITestParams } from "../../types";

export const DESEDE3CBC: ITestParams = {
  name: "DES-EDE3-CBC",
  actions: {
    generateKey: [
      {
        algorithm: { name: "DES-EDE3-CBC", length: 192 } as any,
        extractable: false,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
    ],
    encrypt: [
      {
        algorithm: {
          name: "DES-EDE3-CBC",
          iv: Buffer.from("12345678"),
        } as any,
        data: Buffer.from("test message"),
        encData: Buffer.from("b9ef20e7db926490e4ff8680d99d2141", "hex"),
        key: {
          format: "raw",
          algorithm: { name: "DES-EDE3-CBC" },
          extractable: true,
          keyUsages: ["encrypt", "decrypt"],
          data: Buffer.from("1234567890abcdef12345678"),
        },
      },
    ],
    import: [
      {
        name: "raw",
        format: "raw",
        data: Buffer.from("1234567890abcdef12345678"),
        algorithm: "DES-EDE3-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
      {
        name: "wrong key size",
        error: Error,
        format: "raw",
        data: Buffer.from("12345678"),
        algorithm: "DES-EDE3-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
      {
        name: "jwk",
        format: "jwk",
        data: {
          kty: "oct",
          alg: "3DES-CBC",
          k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
          ext: true,
          key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
        },
        algorithm: "DES-EDE3-CBC",
        extractable: true,
        keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      },
    ],
  },
};