import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { testCrypto, webCrypto } from "./utils";

context("DES", () => {

  testCrypto(webCrypto, [
    {
      name: "DES-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "DES-CBC", length: 64 } as types.DesKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "DES-CBC",
              iv: pvtsutils.Convert.FromUtf8String("12345678"),
            } as types.DesParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("3af3f901ff01fe0102dfbbf37d9bdb94"),
            key: {
              format: "raw",
              algorithm: { name: "DES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
              data: pvtsutils.Convert.FromUtf8String("12345678"),
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("12345678"),
            algorithm: "DES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "DES-CBC",
              k: "MTIzNDU2Nzg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "DES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "DES-EDE3-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "DES-EDE3-CBC", length: 192 } as types.DesKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "DES-EDE3-CBC",
              iv: pvtsutils.Convert.FromUtf8String("12345678"),
            } as types.DesParams,
            data: pvtsutils.Convert.FromUtf8String("test message"),
            encData: pvtsutils.Convert.FromHex("b9ef20e7db926490e4ff8680d99d2141"),
            key: {
              format: "raw",
              algorithm: { name: "DES-EDE3-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
              data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("1234567890abcdef12345678"),
            algorithm: "DES-EDE3-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "wrong key size",
            error: true,
            format: "raw",
            data: pvtsutils.Convert.FromUtf8String("12345678"),
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
    },
  ]);

});
