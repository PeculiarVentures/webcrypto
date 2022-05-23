import { Crypto } from "@peculiar/webcrypto";
// eslint-disable-next-line import/named
import { WebcryptoTest, vectors } from "../src";

const crypto = new Crypto();
WebcryptoTest.check(crypto);
WebcryptoTest.check(crypto, [vectors.SHA]);
WebcryptoTest.check(crypto, {
  AES128CBC: true,
  AES192CBC: true,
  AES256CBC: true,
  AES128CMAC: true,
  AES192CMAC: true,
  AES128CTR: true,
  AES192CTR: true,
  AES256CTR: true,
  AES128ECB: true,
  AES192ECB: true,
  AES256ECB: true,
  AES128GCM: true,
  AES192GCM: true,
  AES256GCM: true,
  AES128KW: true,
  AES192KW: true,
  AES256KW: true,

  DESCBC: true,
  DESEDE3CBC: true,

  RSAESPKCS1: true,
  RSASSAPKCS1: true,
  RSAOAEP: true,
  RSAPSS: true,

  ECDSA: true,
  ECDH: true,

  HKDF: true,
  HMAC: true,
  PBKDF2: true
});
WebcryptoTest.add(crypto, vectors.SHA);