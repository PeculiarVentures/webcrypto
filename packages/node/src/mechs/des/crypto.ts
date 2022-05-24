import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { CryptoKey } from "../../keys";
import { DesCryptoKey } from "./key";

export class DesCrypto {

  public static async generateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<DesCryptoKey> {
    const key = new DesCryptoKey();
    key.algorithm = algorithm;
    key.extractable = extractable;
    key.usages = keyUsages;
    key.data = crypto.randomBytes(algorithm.length >> 3);

    return key;
  }

  public static async exportKey(format: string, key: CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return jsonSchema.JsonSerializer.toJSON(key);
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: types.JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    let key: DesCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: DesCryptoKey });
        break;
      case "raw":
        key = new DesCryptoKey();
        key.data = Buffer.from(keyData as ArrayBuffer);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = algorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  public static async encrypt(algorithm: types.DesParams, key: DesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
        return this.encryptDesCBC(algorithm, key, Buffer.from(data));
      case "DES-EDE3-CBC":
        return this.encryptDesEDE3CBC(algorithm, key, Buffer.from(data));
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async decrypt(algorithm: types.DesParams, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    if (!(key instanceof DesCryptoKey)) {
      throw new Error("key: Is not DesCryptoKey");
    }

    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
        return this.decryptDesCBC(algorithm, key, Buffer.from(data));
      case "DES-EDE3-CBC":
        return this.decryptDesEDE3CBC(algorithm, key, Buffer.from(data));
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async encryptDesCBC(algorithm: types.DesParams, key: DesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`des-cbc`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptDesCBC(algorithm: types.DesParams, key: DesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`des-cbc`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

  public static async encryptDesEDE3CBC(algorithm: types.DesParams, key: DesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv(`des-ede3-cbc`, key.data, Buffer.from(algorithm.iv as ArrayBuffer));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = new Uint8Array(enc).buffer;
    return res;
  }

  public static async decryptDesEDE3CBC(algorithm: types.DesParams, key: DesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv(`des-ede3-cbc`, key.data, new Uint8Array(algorithm.iv as ArrayBuffer));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return new Uint8Array(dec).buffer;
  }

}
