import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestParams, ITestGenerateKeyAction } from "../../types";

export const RSAOAEP: ITestParams = {
  name: "RSA-OAEP",
  actions: {
    generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
      return {
        name: hash,
        algorithm: {
          name: "RSA-OAEP",
          hash,
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 1024,
        } as types.RsaHashedKeyGenParams,
        extractable: false,
        keyUsages: ["encrypt", "decrypt"],
      } as ITestGenerateKeyAction;
    }),
    encrypt: [
      {
        name: "with label",
        algorithm: {
          name: "RSA-OAEP",
          label: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        } as types.RsaOaepParams,
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        encData: Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
        key: {
          publicKey: {
            format: "jwk",
            algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP-256",
              e: "AQAB",
              ext: true,
              key_ops: ["encrypt"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
            },
            extractable: true,
            keyUsages: ["encrypt"],
          },
          privateKey: {
            format: "jwk",
            algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP-256",
              d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
              dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
              dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
              e: "AQAB",
              ext: true,
              key_ops: ["decrypt"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
              p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
              q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
              qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
            },
            extractable: true,
            keyUsages: ["decrypt"],
          },
        },
      },
      {
        name: "without label",
        algorithm: {
          name: "RSA-OAEP",
        } as types.RsaOaepParams,
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        encData: Convert.FromBase64("NcsyyVE/y4Z1K5bWGElWAkvlN+jWpfgPtcytlydWUUz4RqFeW5w6KA1cQMHy3eNh920YXDjsLSYHe6Dz1CEqjIKkHS9HBuOhLA39yUArOu/fmn1lMnwb9N9roTxHDxpgY3y98DXEVkAKU4Py0rlzJLVazDV/+1YcbzFLCSKUNaI="),
        key: {
          publicKey: {
            format: "jwk",
            algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP-256",
              e: "AQAB",
              ext: true,
              key_ops: ["encrypt"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
            },
            extractable: true,
            keyUsages: ["encrypt"],
          },
          privateKey: {
            format: "jwk",
            algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP-256",
              d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
              dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
              dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
              e: "AQAB",
              ext: true,
              key_ops: ["decrypt"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
              p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
              q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
              qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
            },
            extractable: true,
            keyUsages: ["decrypt"],
          },
        },
      },
    ],
  },
};