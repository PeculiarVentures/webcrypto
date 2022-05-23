import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { CryptoKey } from "../../keys";
import { AesCryptoKey } from "./key";

export class AesCrypto {

  public static AES_KW_IV = Buffer.from("A6A6A6A6A6A6A6A6", "hex");

  public static async generateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    const key = new AesCryptoKey();
    key.algorithm = algorithm;
    key.extractable = extractable;
    key.usages = keyUsages;
    key.data = crypto.randomBytes(algorithm.length >> 3);

    return key;
  }

  public static async exportKey(format: string, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    if (!(key instanceof AesCryptoKey)) {
      throw new Error("key: Is not AesCryptoKey");
    }

    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: types.JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    let key: AesCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = JsonParser.fromJSON(keyData, { targetSchema: AesCryptoKey });
        break;
      case "raw":
        key = new AesCryptoKey();
        key.data = Buffer.from(keyData as ArrayBuffer);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = algorithm;
    key.algorithm.length = key.data.length << 3;
    key.extractable = extractable;
    key.usages = keyUsages;

    // check key length
    switch (key.algorithm.length) {
      case 128:
      case 192:
      case 256:
        break;
      default:
        throw new core.OperationError("keyData: Is wrong key length");
    }

    return key;
  }

  public static async encrypt(algorithm: types.Algorithm, key: AesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "AES-CBC":
        return this.encryptAesCBC(algorithm as types.AesCbcParams, key, Buffer.from(data));
      case "AES-CTR":
        return this.encryptAesCTR(algorithm as types.AesCtrParams, key, Buffer.from(data));
      case "AES-GCM":
        return this.encryptAesGCM(algorithm as types.AesGcmParams, key, Buffer.from(data));
      case "AES-KW":
        return this.encryptAesKW(algorithm as types.AesKeyAlgorithm, key, Buffer.from(data));
      case "AES-ECB":
        return this.encryptAesECB(algorithm as types.AesKeyAlgorithm, key, Buffer.from(data));
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async decrypt(algorithm: types.Algorithm, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    if (!(key instanceof AesCryptoKey)) {
      throw new Error("key: Is not AesCryptoKey");
    }

    switch (algorithm.name.toUpperCase()) {
      case "AES-CBC":
        return this.decryptAesCBC(algorithm as types.AesCbcParams, key, Buffer.from(data));
      case "AES-CTR":
        return this.decryptAesCTR(algorithm as types.AesCtrParams, key, Buffer.from(data));
      case "AES-GCM":
        return this.decryptAesGCM(algorithm as types.AesGcmParams, key, Buffer.from(data));
      case "AES-KW":
        return this.decryptAesKW(algorithm as types.AesKeyAlgorithm, key, Buffer.from(data));
      case "AES-ECB":
        return this.decryptAesECB(algorithm as types.AesKeyAlgorithm, key, Buffer.from(data));
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async encryptAesCBC(algorithm: types.AesCbcParams, key: AesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`aes-${key.algorithm.length}-cbc`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptAesCBC(algorithm: types.AesCbcParams, key: AesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`aes-${key.algorithm.length}-cbc`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

  public static async encryptAesCTR(algorithm: types.AesCtrParams, key: AesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`aes-${key.algorithm.length}-ctr`, key.data, Buffer.from(algorithm.counter as ArrayBuffer));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptAesCTR(algorithm: types.AesCtrParams, key: AesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`aes-${key.algorithm.length}-ctr`, key.data, new Uint8Array(algorithm.counter as ArrayBuffer));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

  public static async encryptAesGCM(algorithm: types.AesGcmParams, key: AesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`aes-${key.algorithm.length}-gcm`, key.data, Buffer.from(algorithm.iv as ArrayBuffer), {
      authTagLength: (algorithm.tagLength || 128) >> 3,
    } as any) as crypto.CipherGCM; // NodeJs d.ts doesn't support CipherGCMOptions for createCipheriv
    if (algorithm.additionalData) {
      cipher.setAAD(Buffer.from(algorithm.additionalData as ArrayBuffer));
    }
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final(), cipher.getAuthTag()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptAesGCM(algorithm: types.AesGcmParams, key: AesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`aes-${key.algorithm.length}-gcm`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer)) as crypto.DecipherGCM;
    const tagLength = (algorithm.tagLength || 128) >> 3;
    const enc = data.slice(0, data.length - tagLength);
    const tag = data.slice(data.length - tagLength);
    if (algorithm.additionalData) {
      decipher.setAAD(Buffer.from(algorithm.additionalData as ArrayBuffer));
    }
    decipher.setAuthTag(tag);
    let dec = decipher.update(enc);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

  public static async encryptAesKW(algorithm: types.Algorithm, key: AesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`id-aes${key.algorithm.length}-wrap`, key.data, this.AES_KW_IV);
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    return new Uint8Array(enc).buffer;
  }

  public static async decryptAesKW(algorithm: types.Algorithm, key: AesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`id-aes${key.algorithm.length}-wrap`, key.data, this.AES_KW_IV);
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

  public static async encryptAesECB(algorithm: types.Algorithm, key: AesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`aes-${key.algorithm.length}-ecb`, key.data, new Uint8Array(0));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptAesECB(algorithm: types.Algorithm, key: AesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`aes-${key.algorithm.length}-ecb`, key.data, new Uint8Array(0));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }
}
