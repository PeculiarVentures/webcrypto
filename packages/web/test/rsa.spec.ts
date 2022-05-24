import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { Browser } from "../src/helper";
import { browser, ITestGenerateKeyAction, testCrypto, webCrypto } from "./utils";

context("RSA", () => {

  testCrypto(webCrypto, [
    // RSASSA-PKCS1-v1_5
    {
      name: "RSASSA-PKCS1-v1_5",
      actions: {
        generateKey: (() => {
          const res: ITestGenerateKeyAction[] = [];
          ["SHA-1", "SHA-256"].forEach((hash) =>
            ["SHA-1", "SHA-256", "SHA-512"].forEach((hash) =>
              [new Uint8Array([3]), new Uint8Array([1, 0, 1])].forEach((publicExponent) =>
                [1024, 2048].forEach((modulusLength) => {
                  res.push({
                    name: `h:${hash} e:${pvtsutils.Convert.ToHex(publicExponent)} n:${modulusLength}`,
                    skip: false,
                    algorithm: {
                      name: "RSASSA-PKCS1-v1_5",
                      hash,
                      publicExponent,
                      modulusLength,
                    } as types.RsaHashedKeyGenParams,
                    extractable: false,
                    keyUsages: ["sign", "verify"],
                  } as ITestGenerateKeyAction);
                }),
              ),
            ),
          );
          return res;
        })(),
        sign: [
          {
            name: "SHA-256, e:010001, n:2048",
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
            },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: pvtsutils.Convert.FromBase64("f8OvbYnwX5YPVPjWkOTalYTFJjS1Ks7iNmPdLEby/kK6BEGk5uPvY/ebcok6sTQpQXJXJFJbOcMrZftmJXpm1szcgOdNgVW6FDc3722a9Mzvk/YfvNUCQRNEMON9lYKdpOLSXAFpXR5ovZytbFQ2w2ztpKkJvNY2QZQlizcZKSg="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams,
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
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams,
                data: {
                  alg: "RS256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
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
          {
            name: "SHA-1 e:03 n:1024",
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
            },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: pvtsutils.Convert.FromHex("2f4cab4f67ca544934e462fd324ea0b52f9040f1453c8c425e818411bf54c3c0cd1d7f2a1d04a820ce28fec996b94a0971d481ec8adee2ee0d8b003c2cb75862d7699a73b798d7fab788956ae17388fed764e7a1a944abf9799534b66e830a5c5f4ea7253b937af6b4fcbd11310da3daebf1f3181041bdd550cbe4ea8ff2e1ed"),
            key: {
              publicKey: {
                format: "spki",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as types.Algorithm,
                data: pvtsutils.Convert.FromBase64("MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDL51DUp2Jxqjr18k5mpAvFBzTLtzK4qL6Pq8H4nXU+8gheGYP2+Vi3J+PSLVTIKk7jPNJ2gQtgnA27TNZxYA0QplEyxq0WQwTMp8vz/PAJYjsLNx8O4g433Ve60dUzZWjjbawX8JeggET37m2EoCsgHXJPe3puloMfD0qRR3BoZwIBAw=="),
                extractable: true,
                keyUsages: ["verify"],
              },
              privateKey: {
                format: "pkcs8",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as types.Algorithm,
                data: pvtsutils.Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMvnUNSnYnGqOvXyTmakC8UHNMu3Mriovo+rwfiddT7yCF4Zg/b5WLcn49ItVMgqTuM80naBC2CcDbtM1nFgDRCmUTLGrRZDBMyny/P88AliOws3Hw7iDjfdV7rR1TNlaONtrBfwl6CARPfubYSgKyAdck97em6Wgx8PSpFHcGhnAgEDAoGAIfvizhvlvZxfKP23u8YB9iveIfPdyXF1F/H1qW+Tin2sD67rU9Q5c9v7TbI4zAcNJd94aRWB5W9Xnzd5EuVXgnnU/wz54Bk6zXMLq/L6oouSLzcRVwz0riaXBa007OTejfS+jVhCAlMM4hqYnCxrRr4BBIEi+WidyHKSs8ynSE8CQQD9BRizPsw8eZXDcJz1TVrNYVk4ZGgWfmgGkdyeSh2A5Smdcmvzcm32dNVH9fqL9P33qoJUw+CoSRKuEB/szIjjAkEAzk4fxZMJbypmMhVPVcLfT2yWtFKcfdO67zu8JE2Ih0xmE8Jb65kkl4LWBuPhCbJ5scGyH+S1eodZsco6jrgtrQJBAKiuEHd/MtL7uSz1vfjePIjrkNBC8A7+8ARhPb7cE6tDcROhnUz28/mjONqj/F1N/qUcVuMtQHAwtx61ap3dsJcCQQCJiWqDt1ufcZl2uN+Ogeo08w8i4b2pN9H00n1tiQWviEQNLD1Hu226VzlZ7UCxIaZ2gSFqmHj8WjvL3CcJ0B5zAkEAlmRgnALghAcJ/WfTMphPKJXhY+H+CgkeE3si2ZgPW1YaDAyhp/xdQabkgbFy70Nq32fuJyxDDS4WhF0aOYz6pw=="),
                extractable: true,
                keyUsages: ["sign"],
              },
            },
          },
        ],
        import: [
          { // public key JWK
            name: "public key JWK",
            format: "jwk",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.Algorithm,
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
          { // public key SPKI
            name: "public key SPKI",
            format: "spki",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.Algorithm,
            data: pvtsutils.Convert.FromBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+qm93G7JnqspidZOP9nMMEVkAACWl7mGmiJgepraPmQru/xTkRo9jZsuJv2bgHjSP6fcVX3FQIaKmVZ2owkkpP7g+MY7kTdLg32SMWG7nuehhPvPvfTYnSwld6gVtfGWAT7gbnk7GWbnYgPb9El6w/mfNwZOuJDChFusk/k4S3QIDAQAB"),
            extractable: true,
            keyUsages: ["verify"],
          },
          { // private key JWK
            name: "private key JWK",
            format: "jwk",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.Algorithm,
            data: {
              alg: "RS256",
              d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
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
            skip: browser.name === Browser.Edge, // Edge returns PKCS8 with KeyUsages extension
            name: "private key pkcs8",
            format: "pkcs8",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.Algorithm,
            data: pvtsutils.Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL6qb3cbsmeqymJ1k4/2cwwRWQAAJaXuYaaImB6mto+ZCu7/FORGj2Nmy4m/ZuAeNI/p9xVfcVAhoqZVnajCSSk/uD4xjuRN0uDfZIxYbue56GE+8+99NidLCV3qBW18ZYBPuBueTsZZudiA9v0SXrD+Z83Bk64kMKEW6yT+ThLdAgMBAAECgYACR4hYnLCn059iyPQQKwqaENUHDnlkv/JT6tsitqyFD/fU/qCxz/Qj5JU3Wt3wfPv04n+tNjxlEFng8jIV0+jK+6jlqkd0AcfquIkrEMdY/GET5F41UQ9JOIXWvLwNJ7nMLvD0Eucf9AzxuQ3hw6e+CquDsRusZaiYAYlW+hHA4wJBAOoxbZgSSUBSJUFF12WCILx+9GPWtN6Fiozbhdr3m+WX9PRLSzRPOjaZyJuOtzp6ByT1tJvMBxV2WX3GFUyD0f8CQQDQa20MyXWQjNJXas3MZek5Ly1SqvkvPQS1VnAhv0Yk8yYnQ/eBnzTXMSBlnj56xTtwtR/4FJkQCZ+coDzQbaMjAkEApOolqL7HwnmWLn7GDX8zGkm0Q1IAj+ouBL7ZZbaTm3wETLtwu+dGsQheEdzP/mfL/CTiCAwGuQBcSItimD0DdQJAFTSY59AnkgmB7TsErWNBE3xlVB/pMpE2xWyCBCz96gyDOUOFDz8vlSV+clhjawJeRd1n30nZOPSBtOHozhwZmQJAFByTxX4G2eXkk1xe0IuiEv7I5NS+CnFyp8iB4XLG0rabnfcIZFKpf//X0sNyVOAVo5+jJMuUYjCRTdaXNAWhkg=="),
            extractable: true,
            keyUsages: ["sign"],
          },
          {
            name: "pkcs8 e:03 n:1024",
            skip: browser.name === Browser.Edge,
            format: "pkcs8",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as types.Algorithm,
            data: pvtsutils.Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMvnUNSnYnGqOvXyTmakC8UHNMu3Mriovo+rwfiddT7yCF4Zg/b5WLcn49ItVMgqTuM80naBC2CcDbtM1nFgDRCmUTLGrRZDBMyny/P88AliOws3Hw7iDjfdV7rR1TNlaONtrBfwl6CARPfubYSgKyAdck97em6Wgx8PSpFHcGhnAgEDAoGAIfvizhvlvZxfKP23u8YB9iveIfPdyXF1F/H1qW+Tin2sD67rU9Q5c9v7TbI4zAcNJd94aRWB5W9Xnzd5EuVXgnnU/wz54Bk6zXMLq/L6oouSLzcRVwz0riaXBa007OTejfS+jVhCAlMM4hqYnCxrRr4BBIEi+WidyHKSs8ynSE8CQQD9BRizPsw8eZXDcJz1TVrNYVk4ZGgWfmgGkdyeSh2A5Smdcmvzcm32dNVH9fqL9P33qoJUw+CoSRKuEB/szIjjAkEAzk4fxZMJbypmMhVPVcLfT2yWtFKcfdO67zu8JE2Ih0xmE8Jb65kkl4LWBuPhCbJ5scGyH+S1eodZsco6jrgtrQJBAKiuEHd/MtL7uSz1vfjePIjrkNBC8A7+8ARhPb7cE6tDcROhnUz28/mjONqj/F1N/qUcVuMtQHAwtx61ap3dsJcCQQCJiWqDt1ufcZl2uN+Ogeo08w8i4b2pN9H00n1tiQWviEQNLD1Hu226VzlZ7UCxIaZ2gSFqmHj8WjvL3CcJ0B5zAkEAlmRgnALghAcJ/WfTMphPKJXhY+H+CgkeE3si2ZgPW1YaDAyhp/xdQabkgbFy70Nq32fuJyxDDS4WhF0aOYz6pw=="),
            extractable: true,
            keyUsages: ["sign"],
          },
          {
            name: "spki e:03 n:1024",
            format: "spki",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as types.Algorithm,
            data: pvtsutils.Convert.FromBase64("MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDL51DUp2Jxqjr18k5mpAvFBzTLtzK4qL6Pq8H4nXU+8gheGYP2+Vi3J+PSLVTIKk7jPNJ2gQtgnA27TNZxYA0QplEyxq0WQwTMp8vz/PAJYjsLNx8O4g433Ve60dUzZWjjbawX8JeggET37m2EoCsgHXJPe3puloMfD0qRR3BoZwIBAw=="),
            extractable: true,
            keyUsages: ["verify"],
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
            signature: pvtsutils.Convert.FromBase64("OYz/7fv71ELOs5kuz5IiYq1NsXuOazl22xqIFjiY++hYFzJMWaR+ZI0WPoMOifvb1PNKmdQ4dY+QbpYC1vdzlAKfkLe22l5htLyQaXzjD/yeMZYrL0KmrabC9ayL6bxrMW+ccePStkbrF1Jn0LT09l22aX/r1y3SPrl0b+zwo/Q="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-PSS", hash: "SHA-256" } as types.Algorithm,
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
                algorithm: { name: "RSA-PSS", hash: "SHA-256" } as types.Algorithm,
                data: {
                  alg: "PS256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
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
            encData: pvtsutils.Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.Algorithm,
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
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.Algorithm,
                data: {
                  alg: "RSA-OAEP-256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
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
            encData: pvtsutils.Convert.FromBase64("d91eZMLqHTOIGC+GqfSj13x8aQHkTKqxImwmybFFpR/00n5y4e7tL7XX49izZO/wwgCYkDCentX7BGoPhOv/4RhW9vVlfrjFAFdwZFAOFlumt+9jp2QjBDnwxuoCO/IOhjFFf7rq5hTBUB9eoHsSMp42LA6F/Q3IuxFLaejOWGw="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.Algorithm,
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
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" } as types.Algorithm,
                data: {
                  alg: "RSA-OAEP-256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
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
    // RSAES-PKCS1-v1_5
    {
      name: "RSAES-PKCS1-v1_5",
      actions: {
        generateKey: [
          {
            algorithm: {
              name: "RSAES-PKCS1-v1_5",
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 1024,
            } as types.RsaKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt"],
          } as ITestGenerateKeyAction,
        ],
        encrypt: [
          {
            algorithm: {
              name: "RSAES-PKCS1-v1_5",
            } as types.Algorithm,
            data: pvtsutils.Convert.FromHex("01435e62ad3ec4850720e34f8cab620e203749f2315b203d"),
            encData: pvtsutils.Convert.FromHex("76e5ea6e1df52471454f790923f60e2baa7adf5017fe0a36c0af3e32f6390d570e1d592375ba6035fdf4ffa70764b797ab54d0ab1efe89cf31d7fc98240a4d08c2476b7eb4c2d92355b8bf60e3897c3fcbfe09f20c7b159d9a9c4a6b2ce5021dd313e492afa762c24930f97f03a429f7b2b1e1d6088651d60e323835807c6fefe7952f74e5da29e8e327ea46e69a0a6684272f022bf18ec602ffcd10a62666b35a51ec7c7d101096f663ddfa0924a86bdbcde0433b4f71dc42bfd9facf329558026f8667f1a71c3365e09843a12339d8aaf31987b0d800e53fd0835e990096cb145e278153faf1188cd5713c6fcd289cb77d80515e1d200139b8ccac4d3bcebc"),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSAES-PKCS1-v1_5" } as types.Algorithm,
                data: {
                  alg: "RS1",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["encrypt"],
                  kty: "RSA",
                  n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
                },
                extractable: true,
                keyUsages: ["encrypt"],
              },
              privateKey: {
                format: "jwk",
                algorithm: { name: "RSAES-PKCS1-v1_5" } as types.Algorithm,
                data: {
                  kty: "RSA",
                  alg: "RS1",
                  key_ops: ["decrypt"],
                  ext: true,
                  n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
                  e: "AQAB",
                  d: "kZ2IoQ3G7UcshMdL8kC85vadW7wktldLtkqqf1qSVIo6cOfTJCWJe5yrWPG_VIJjfkeQgOh2hHKRjcV67HfwwWEZr-IrPMu6R1_DRPSxYdohiNUnUEi7TlkJ1tT882OF74rWQeaIZIS13wzjUk7_XjKWHsfO1d6t9dwWbiYx1nj4syQCcUrvHIgVXCfL85Tyu3NHqpxOdbzRb2OLmkv5ciHFExm4ai98xAgsEXbNvZQeSOOfKNsiCb-NjBXLYrbaDIsakAEV75893JubfeD51UHn7dPT8M8MmKEvrTOKCscShf01scTDHfx_hiOXK3XG4tVx9l2YGEkt3xCedljocQ",
                  p: "_dWMJ57SECcBbOjPRCvT97ypDyw9ydvnSZXTsn9c7ScxvUxBk6-wuMtgsLI8OWkhZGDBLyVrn-I3RMAN-A5QI_adoGdK7fq5lFWmQYvb1u1xUaGEInVFsM3BW7RBBF8N7OzHwULEQLTXb4jkpgwyCynsX0OEbVVvVerqrcr7osM",
                  q: "yHEjuQe9TNo-leMrL6cu-yDPfA85M8xQuBM59Cwz06-ggBRi9EOpbV-CrejGUbVlE9QmKGqIBT8C3NVBQwybzlgUihgIpnVgkb01lLEf13ohQ_GWV1mS8ybznjMgaVtVF5Lva4WixIDlXbOu4svVQpkr-KRpKvEMUCTsX-Sxx7k",
                  dp: "jMP4TaCN7dczuyoAh1Wm3yQIvRlTyrXgtbYZCEwJRJsPwmKfmz87Sb-_hz3QmCXtFrVxbKvb23agH8hB9uY5GziQgXvG2eLJN7Gn2YGuEKrsxNBFbraKR1pTeH-l7r6oAlPtEwfrvdaMApZv9oWc2wQMyWev8NIIRCVar7Z5hfE",
                  dq: "wi2g3sJZp9cRpGEDWFHM2KnrdxLEZqK7W-f8T8h2mM9eXFXjmyDlRLivP0zuuv9QoUn3gVXa2cI2QrsxUwQm-Fop47Hux1uUpvs2qgqBf1yoV0r2Sz7Sdk442fxLnOVG5OSKno5Cpbz89q54cOvoeHEswN59p4UHWai7eRZzB7k",
                  qi: "k9hlEyvZCWj8Fvxrknj5WHgaLrSqaVku3PVod2wUJox3aZ8vUsGmmD27lfiWwVKNRmgxLiazY40pLPu07SEmlJgF8QjzDb33k5Pcn9wRuezcCi-53LBRK6-EptZ-UjEINBlM_Cx_WOuxs7P77pwcCo2NV76ilxP5PP_34SUZ0ts",
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
