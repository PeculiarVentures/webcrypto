import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import {
  assertBufferSource, toArrayBuffer, toUint8Array,
} from "@peculiar/utils";
import * as core from "webcrypto-core";
import { DesParams } from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { DesCryptoKey } from "./key";

export class DesCrypto {
  public static async generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<DesCryptoKey> {
    const key = new DesCryptoKey();
    key.algorithm = algorithm;
    key.extractable = extractable;
    key.usages = keyUsages;
    key.data = crypto.randomBytes(algorithm.length >> 3);

    return key;
  }

  public static async exportKey(format: string, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "raw":
        return toArrayBuffer(key.data);
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    let key: DesCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = JsonParser.fromJSON(keyData, { targetSchema: DesCryptoKey });
        break;
      case "raw":
        assertBufferSource(keyData);
        key = new DesCryptoKey();
        key.data = Buffer.from(toUint8Array(keyData));
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = algorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  public static async encrypt(algorithm: DesParams, key: DesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
        return this.encryptDesCBC(algorithm, key, Buffer.from(data));
      case "DES-EDE3-CBC":
        return this.encryptDesEDE3CBC(algorithm, key, Buffer.from(data));
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async decrypt(algorithm: DesParams, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
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

  public static async encryptDesCBC(algorithm: DesParams, key: DesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv("des-cbc", key.data, toUint8Array(algorithm.iv));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = toArrayBuffer(enc);
    return res;
  }

  public static async decryptDesCBC(algorithm: DesParams, key: DesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv("des-cbc", key.data, toUint8Array(algorithm.iv));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return toArrayBuffer(dec);
  }

  public static async encryptDesEDE3CBC(algorithm: DesParams, key: DesCryptoKey, data: Buffer) {
    const cipher = crypto.createCipheriv("des-ede3-cbc", key.data, Buffer.from(toUint8Array(algorithm.iv)));
    let enc = cipher.update(data);
    enc = Buffer.concat([enc, cipher.final()]);
    const res = toArrayBuffer(enc);
    return res;
  }

  public static async decryptDesEDE3CBC(algorithm: DesParams, key: DesCryptoKey, data: Buffer) {
    const decipher = crypto.createDecipheriv("des-ede3-cbc", key.data, toUint8Array(algorithm.iv));
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return toArrayBuffer(dec);
  }
}
