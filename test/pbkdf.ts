import { Convert } from "pvtsutils";
import { Crypto } from "../src";
import { testCrypto } from "./helper";

context("PBKDF", () => {

  const crypto = new Crypto();

  testCrypto(crypto, [
    {
      name: "PBKDF2",
      actions: {
        deriveBits: [
          {
            key: {
              format: "raw",
              data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
              algorithm: {
                name: "PBKDF2",
              },
              extractable: false,
              keyUsages: ["deriveBits"],
            },
            algorithm: {
              name: "PBKDF2",
              salt: new Uint8Array([1, 2, 3, 4]),
              hash: "SHA-256",
              iterations: 1000,
            } as Pbkdf2Params,
            data: Convert.FromBase64("3GK58/4RT+UPLooz5HT1MQ=="),
            length: 128,
          },
        ],
        deriveKey: [
          {
            key: {
              format: "raw",
              data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
              algorithm: {
                name: "PBKDF2",
              },
              extractable: false,
              keyUsages: ["deriveKey"],
            },
            algorithm: {
              name: "PBKDF2",
              salt: new Uint8Array([1, 2, 3, 4]),
              hash: "SHA-256",
              iterations: 1000,
            } as Pbkdf2Params,
            derivedKeyType: {
              name: "AES-CBC",
              length: 128,
            } as AesDerivedKeyParams,
            keyUsages: ["encrypt"],
            format: "raw",
            keyData: Convert.FromBase64("3GK58/4RT+UPLooz5HT1MQ=="),
          },
        ],
      },
    },
  ]);
});
