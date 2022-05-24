import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { nativeCrypto } from "../../native";
import { isAlgorithm } from "../../utils";
import { AesCryptoKey } from "./key";

export class AesCrypto {

  public static AesCBC = "AES-CBC";
  public static AesECB = "AES-ECB";
  public static AesGCM = "AES-GCM";

  public static checkCryptoKey(key: any) {
    if (!(key instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not AesCryptoKey");
    }
  }

  public static async generateKey(algorithm: types.AesKeyGenParams, extractable: boolean, usages: types.KeyUsage[]) {
    // gat random bytes for key
    const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));

    return new AesCryptoKey(algorithm, extractable, usages, raw);
  }

  public static async encrypt(algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer) {
    return this.cipher(algorithm, key, pvtsutils.BufferSourceConverter.toUint8Array(data), true);
  }

  public static async decrypt(algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer) {
    return this.cipher(algorithm, key, pvtsutils.BufferSourceConverter.toUint8Array(data), false);
  }

  public static async exportKey(format: string, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format) {
      case "jwk":
        return key.toJSON();
      case "raw":
        return key.raw.buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    let raw: ArrayBuffer;

    if (core.isJWK(keyData)) {
      if (!keyData.k) {
        throw new core.RequiredPropertyError("k", "JWK");
      }
      raw = pvtsutils.Convert.FromBase64Url(keyData.k);
    } else {
      raw = pvtsutils.BufferSourceConverter.toArrayBuffer(keyData);
    }

    // check key length
    switch (raw.byteLength << 3) {
      case 128:
      case 192:
      case 256:
        break;
      default:
        throw new core.OperationError("keyData: Is wrong key length");
    }

    const key = new AesCryptoKey({ name: algorithm.name, length: raw.byteLength << 3 }, extractable, keyUsages, new Uint8Array(raw));
    return key;
  }

  private static async cipher(algorithm: types.Algorithm, key: AesCryptoKey, data: Uint8Array, encrypt: boolean) {
    const action = encrypt ? "encrypt" : "decrypt";
    let result: Uint8Array;
    if (isAlgorithm<types.AesCbcParams>(algorithm, AesCrypto.AesCBC)) {
      // AES-CBC
      const iv = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.iv);
      result = asmCrypto.AES_CBC[action](data, key.raw, undefined, iv);
    } else if (isAlgorithm<types.AesGcmParams>(algorithm, AesCrypto.AesGCM)) {
      // AES-GCM
      const iv = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.iv);
      let additionalData;
      if (algorithm.additionalData) {
        additionalData = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.additionalData);
      }
      const tagLength = (algorithm.tagLength || 128) / 8;
      result = asmCrypto.AES_GCM[action](data, key.raw, iv, additionalData, tagLength);
    } else if (isAlgorithm<types.Algorithm>(algorithm, AesCrypto.AesECB)) {
      //   // AES-ECB
      result = asmCrypto.AES_ECB[action](data, key.raw, true);
    } else {
      throw new core.OperationError(`algorithm: Is not recognized`);
    }

    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

}
