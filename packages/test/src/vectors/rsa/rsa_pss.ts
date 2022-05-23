import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestParams, ITestGenerateKeyAction } from "../../types";

export const RSAPSS: ITestParams = {
  name: "RSA-PSS",
  actions: {
    generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
      return {
        name: hash,
        algorithm: {
          name: "RSA-PSS",
          hash,
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 1024,
        } as types.RsaHashedKeyGenParams,
        extractable: false,
        keyUsages: ["sign", "verify"],
      } as ITestGenerateKeyAction;
    }),
    sign: [
      {
        algorithm: {
          name: "RSA-PSS",
          saltLength: 64,
        } as types.RsaPssParams,
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        signature: Convert.FromBase64("OYz/7fv71ELOs5kuz5IiYq1NsXuOazl22xqIFjiY++hYFzJMWaR+ZI0WPoMOifvb1PNKmdQ4dY+QbpYC1vdzlAKfkLe22l5htLyQaXzjD/yeMZYrL0KmrabC9ayL6bxrMW+ccePStkbrF1Jn0LT09l22aX/r1y3SPrl0b+zwo/Q="),
        key: {
          publicKey: {
            format: "jwk",
            algorithm: { name: "RSA-PSS", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "PS256",
              e: "AQAB",
              ext: true,
              key_ops: ["verify"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
            },
            extractable: true,
            keyUsages: ["verify"],
          },
          privateKey: {
            format: "jwk",
            algorithm: { name: "RSA-PSS", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "PS256",
              d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
              dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
              dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
              e: "AQAB",
              ext: true,
              key_ops: ["sign"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
              p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
              q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
              qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
            },
            extractable: true,
            keyUsages: ["sign"],
          },
        },
      },
    ],
  },
};