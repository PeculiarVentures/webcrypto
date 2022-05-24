import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { Crypto } from "../../crypto";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export type RsaPkcs1Params = types.Algorithm;
export type RsaPkcs1SignParams = types.HashedAlgorithm;

export class RsaEsProvider extends core.ProviderCrypto {

  public name = "RSAES-PKCS1-v1_5";
  public usages = {
    publicKey: ["encrypt", "wrapKey"] as types.KeyUsages,
    privateKey: ["decrypt", "unwrapKey"] as types.KeyUsages,
  };
  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public override async onGenerateKey(algorithm: types.RsaKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public override checkGenerateKeyParams(algorithm: types.RsaKeyGenParams) {
    // public exponent
    this.checkRequiredProperty(algorithm, "publicExponent");
    if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
      throw new TypeError("publicExponent: Missing or not a Uint8Array");
    }
    const publicExponent = pvtsutils.Convert.ToBase64(algorithm.publicExponent);
    if (!(publicExponent === "Aw==" || publicExponent === "AQAB")) {
      throw new TypeError("publicExponent: Must be [3] or [1,0,1]");
    }

    // modulus length
    this.checkRequiredProperty(algorithm, "modulusLength");
    switch (algorithm.modulusLength) {
      case 1024:
      case 2048:
      case 4096:
        break;
      default:
        throw new TypeError("modulusLength: Must be 1024, 2048, or 4096");
    }
  }

  public override async onDecrypt(algorithm: RsaPkcs1Params, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // EM = 0x00 || 0x02 || PS || 0x00 || M
    const EM = new asmCrypto.RSA(key.data).decrypt(new asmCrypto.BigNumber(pvtsutils.BufferSourceConverter.toUint8Array(data))).result;
    const k = key.algorithm.modulusLength >> 3;
    if (data.byteLength !== k) {
      throw new core.CryptoError("Decryption error. Encrypted message size doesn't match to key length");
    }
    // If the first octet of EM does not have hexadecimal value 0x00, if
    // the second octet of EM does not have hexadecimal value 0x02, if
    // there is no octet with hexadecimal value 0x00 to separate PS from
    // M, or if the length of PS is less than 8 octets, output
    // "decryption error" and stop.
    let offset = 0;
    if (EM[offset++] || EM[offset++] !== 2) {
      throw new core.CryptoError("Decryption error");
    }
    do {
      if (EM[offset++] === 0) {
        break;
      }
    } while (offset < EM.length);

    if (offset < 11) {
      throw new core.CryptoError("Decryption error. PS is less than 8 octets.");
    }

    if (offset === EM.length) {
      throw new core.CryptoError("Decryption error. There is no octet with hexadecimal value 0x00 to separate PS from M");
    }

    return EM.buffer.slice(offset);
  }

  public override async onEncrypt(algorithm: RsaPkcs1Params, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const k = key.algorithm.modulusLength >> 3;
    if (data.byteLength > k - 11) {
      throw new core.CryptoError("Message too long");
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    const psLen = k - data.byteLength - 3;
    const PS = RsaCrypto.randomNonZeroValues(new Uint8Array(psLen));
    const EM = new Uint8Array(k);
    EM[0] = 0;
    EM[1] = 2;
    EM.set(PS, 2); // PS
    EM[2 + psLen] = 0;
    EM.set(new Uint8Array(data), 3 + psLen);

    const result = new asmCrypto.RSA(key.data).encrypt(new asmCrypto.BigNumber(EM)).result;
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public override async onExportKey(format: types.KeyFormat, key: RsaCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public override async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is RsaCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

  private async prepareSignData(algorithm: RsaPkcs1SignParams, data: ArrayBuffer) {
    const crypto = new Crypto();
    return crypto.subtle.digest(algorithm.hash, data);
  }
}
