import * as types from "@peculiar/webcrypto-types";
import * as test from "@peculiar/webcrypto-test";
import * as config from "./config";
import { isNSS, isSoftHSM } from "./helper";

function fixEcImport(item: test.ITestImportAction) {
  if (item.name?.startsWith("JWK private key")) {
    const jwk = item.data as types.JsonWebKey;
    delete jwk.x;
    delete jwk.y;
  }
  if (item.name?.startsWith("PKCS8 P-256")) {
    item.data = Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420895118e4e168dc9ee0d419d2c3f5845b2918fda96b84d9a91012f2ffb70d9ee1", "hex");
  }
  if (item.name?.startsWith("PKCS8 P-384")) {
    item.data = Buffer.from("304e020100301006072a8648ce3d020106052b8104002204373035020101043098d7c6a318f0a02efe1a17552492884c11a079314d4cc9f92e1504905436072d61539fc7fd73371eeda4c80e3902c743", "hex");
  }
  if (item.name?.startsWith("PKCS8 P-521")) {
    item.data = Buffer.from("3060020100301006072a8648ce3d020106052b81040023044930470201010442006c71a419f8a4e6ad25f99308ef475ba5319678acb5f9cde61bdf301e69e953e7766c0adc603397728aa0e4873fa679ad1efc6693e125df7bb75e880638d28f968b", "hex");
  }
}

// Fix EC import tests.
// PKCS#11 doesn't return public key from private key
test.vectors.ECDSA.actions.import?.forEach(fixEcImport);
test.vectors.ECDH.actions.import?.forEach(fixEcImport);
test.vectors.ECDH.actions.deriveKey?.forEach((item) => {
  if (item.name === "P-521 256") {
    // module doesn't support AES-CTR
    item.derivedKeyType.name = "AES-CBC";
  }
});

// WebcryptoTest.check(config.crypto, [
//   vectors.AES128CBC,
// ]);
test.WebcryptoTest.check(config.crypto, {
  AES128KW: true,
  AES192KW: true,
  AES256KW: true,
  RSAOAEP: true,
  PBKDF2: true,
  HKDF: true,
  DESCBC: true,
  DESEDE3CBC: true,
  RSAESPKCS1: true,
  AES128CMAC: true,
  AES192CMAC: true,
  AES256CMAC: true,
  AES128CTR: true,
  AES192CTR: true,
  AES256CTR: true,
});

test.WebcryptoTest.add(config.crypto, {
  name: "RSA-OAEP-SHA1",
  actions: {
    encrypt: [
      {
        skip: isNSS("RSA-OAEP-SHA1 throws CKR_DEVICE_ERROR"),
        name: "without label",
        algorithm: {
          name: "RSA-OAEP",
        } as types.Algorithm,
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        encData: Buffer.from("MAKiRseL08AlR8Fmn1uVz/lDDdrDiRyI6KUW3mcE/0kxwW7/VizQJP+jiTSWyHexhQ+Sp0ugm6Doa/jahajuVf0aFkqJCcEKlSeMGvu4QdDc9tJzeNJVqSbPovFy60Criyjei4ganw2RQM2Umav//HfQEyqGTcyftMxXzkDDBQU=", "base64"),
        key: {
          publicKey: {
            format: "jwk",
            algorithm: { name: "RSA-OAEP", hash: "SHA-1" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP",
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
            algorithm: { name: "RSA-OAEP", hash: "SHA-1" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP",
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
        skip: isSoftHSM("RSA-OAEP-SHA1 supports encryption without label only")
          || isNSS("RSA-OAEP-SHA1 throws CKR_DEVICE_ERROR"),
        name: "with label",
        algorithm: {
          name: "RSA-OAEP",
          label: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        } as types.RsaOaepParams,
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        encData: Buffer.from("YLtmJDT8Y4Z2Y/VoGHUvhgs5kptNShFRUCcsKpUgI9A+YCYXL3K8fnEkbzO/Nkd4/0RsvfnmXkUJg3JdzPslwO1bOdlNsd2hRi0qi4cpxVmHDjuI3EHMb7FI3Pb9cF/kMFeEQzttpIDqh/UQJnoyh4d/RyZS1w37Vk0sNer7xw0=", "base64"),
        key: {
          publicKey: {
            format: "jwk" as types.KeyFormat,
            algorithm: { name: "RSA-OAEP", hash: "SHA-1" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP",
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
            algorithm: { name: "RSA-OAEP", hash: "SHA-1" } as types.RsaHashedImportParams,
            data: {
              alg: "RSA-OAEP",
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
});
