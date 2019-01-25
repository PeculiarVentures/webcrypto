import { Convert } from "pvtsutils";
import { Crypto } from "../src";
import { ITestGenerateKeyAction, testCrypto } from "./helper";

context("RSA", () => {

  const crypto = new Crypto();

  testCrypto(crypto, [
    // RSASSA-PKCS1-v1_5
    {
      name: "RSASSA-PKCS1-v1_5",
      actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
          return {
            name: hash,
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
              hash,
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 1024,
            } as RsaHashedKeyGenParams,
            extractable: false,
            keyUsages: ["sign", "verify"],
          } as ITestGenerateKeyAction;
        }),
        sign: [
          {
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
            },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromBase64("f8OvbYnwX5YPVPjWkOTalYTFJjS1Ks7iNmPdLEby/kK6BEGk5uPvY/ebcok6sTQpQXJXJFJbOcMrZftmJXpm1szcgOdNgVW6FDc3722a9Mzvk/YfvNUCQRNEMON9lYKdpOLSXAFpXR5ovZytbFQ2w2ztpKkJvNY2QZQlizcZKSg="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                  alg: "RS256",
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
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                  alg: "RS256",
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
        import: [
          {
            name: "public key JWK",
            format: "jwk" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: {
              alg: "RS256",
              e: "AQAB",
              ext: true,
              key_ops: ["verify"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
            },
            extractable: true,
            keyUsages: ["verify"],
          },
          {
            name: "public key SPKI",
            format: "spki" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: Convert.FromBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+qm93G7JnqspidZOP9nMMEVkAACWl7mGmiJgepraPmQru/xTkRo9jZsuJv2bgHjSP6fcVX3FQIaKmVZ2owkkpP7g+MY7kTdLg32SMWG7nuehhPvPvfTYnSwld6gVtfGWAT7gbnk7GWbnYgPb9El6w/mfNwZOuJDChFusk/k4S3QIDAQAB"),
            extractable: true,
            keyUsages: ["verify"],
          },
          {
            name: "private key JWK",
            format: "jwk" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: {
              alg: "RS256",
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
          {
            name: "private key pkcs8",
            format: "pkcs8" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL6qb3cbsmeqymJ1k4/2cwwRWQAAJaXuYaaImB6mto+ZCu7/FORGj2Nmy4m/ZuAeNI/p9xVfcVAhoqZVnajCSSk/uD4xjuRN0uDfZIxYbue56GE+8+99NidLCV3qBW18ZYBPuBueTsZZudiA9v0SXrD+Z83Bk64kMKEW6yT+ThLdAgMBAAECgYACR4hYnLCn059iyPQQKwqaENUHDnlkv/JT6tsitqyFD/fU/qCxz/Qj5JU3Wt3wfPv04n+tNjxlEFng8jIV0+jK+6jlqkd0AcfquIkrEMdY/GET5F41UQ9JOIXWvLwNJ7nMLvD0Eucf9AzxuQ3hw6e+CquDsRusZaiYAYlW+hHA4wJBAOoxbZgSSUBSJUFF12WCILx+9GPWtN6Fiozbhdr3m+WX9PRLSzRPOjaZyJuOtzp6ByT1tJvMBxV2WX3GFUyD0f8CQQDQa20MyXWQjNJXas3MZek5Ly1SqvkvPQS1VnAhv0Yk8yYnQ/eBnzTXMSBlnj56xTtwtR/4FJkQCZ+coDzQbaMjAkEApOolqL7HwnmWLn7GDX8zGkm0Q1IAj+ouBL7ZZbaTm3wETLtwu+dGsQheEdzP/mfL/CTiCAwGuQBcSItimD0DdQJAFTSY59AnkgmB7TsErWNBE3xlVB/pMpE2xWyCBCz96gyDOUOFDz8vlSV+clhjawJeRd1n30nZOPSBtOHozhwZmQJAFByTxX4G2eXkk1xe0IuiEv7I5NS+CnFyp8iB4XLG0rabnfcIZFKpf//X0sNyVOAVo5+jJMuUYjCRTdaXNAWhkg=="),
            extractable: true,
            keyUsages: ["sign"],
          },
        ],
      },
    },
    // RSA-PSS
    {
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
            } as RsaHashedKeyGenParams,
            extractable: false,
            keyUsages: ["sign", "verify"],
          } as ITestGenerateKeyAction;
        }),
        sign: [
          {
            algorithm: {
              name: "RSA-PSS",
              saltLength: 64,
            } as RsaPssParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromBase64("OYz/7fv71ELOs5kuz5IiYq1NsXuOazl22xqIFjiY++hYFzJMWaR+ZI0WPoMOifvb1PNKmdQ4dY+QbpYC1vdzlAKfkLe22l5htLyQaXzjD/yeMZYrL0KmrabC9ayL6bxrMW+ccePStkbrF1Jn0LT09l22aX/r1y3SPrl0b+zwo/Q="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-PSS", hash: "SHA-256" },
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
                algorithm: { name: "RSA-PSS", hash: "SHA-256" },
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
    },
    // RSA-OAEP
    {
      name: "RSA-OAEP",
      actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
          return {
            name: hash,
            skip: true,
            algorithm: {
              name: "RSA-OAEP",
              hash,
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 1024,
            } as RsaHashedKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt"],
          } as ITestGenerateKeyAction;
        }),
        encrypt: [
          {
            name: "with label",
            skip: true,
            algorithm: {
              name: "RSA-OAEP",
              label: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            } as RsaOaepParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            encData: Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
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
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
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
            skip: true,
            algorithm: {
              name: "RSA-OAEP",
            } as RsaOaepParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            encData: Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
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
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
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
    },
  ]);

});
