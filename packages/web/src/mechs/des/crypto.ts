/// <reference path="../../typings/des.d.ts" />

import * as core from "@peculiar/webcrypto-core";
import { RequiredPropertyError } from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as des from "des.js";
import * as pvtsutils from "pvtsutils";
import { nativeCrypto } from "../../native";
import { DesCryptoKey } from "./key";

export class DesCrypto {

  public static checkLib() {
    if (typeof (des) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/des.js' script to your project");
    }
  }

  public static checkCryptoKey(key: any) {
    if (!(key instanceof DesCryptoKey)) {
      throw new TypeError("key: Is not DesCryptoKey");
    }
  }

  public static async generateKey(algorithm: types.DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<DesCryptoKey> {
    this.checkLib();

    // gat random bytes for key
    const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));

    return new DesCryptoKey(algorithm, extractable, keyUsages, raw);
  }

  public static async exportKey(format: types.KeyFormat, key: DesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    this.checkLib();

    switch (format) {
      case "jwk":
        return key.toJSON();
      case "raw":
        return key.raw.buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.DesImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<DesCryptoKey> {
    this.checkLib();

    let raw: ArrayBuffer;

    if (core.isJWK(keyData)) {
      if (!keyData.k) {
        throw new RequiredPropertyError("k", "JWK");
      }
      raw = pvtsutils.Convert.FromBase64Url(keyData.k);
    } else {
      raw = pvtsutils.BufferSourceConverter.toArrayBuffer(keyData);
    }

    // check key length
    if ((algorithm.name === "DES-CBC" && raw.byteLength !== 8)
      || (algorithm.name === "DES-EDE3-CBC" && raw.byteLength !== 24)) {
      throw new core.OperationError("keyData: Is wrong key length");
    }

    const key = new DesCryptoKey({ name: algorithm.name, length: raw.byteLength << 3 }, extractable, keyUsages, new Uint8Array(raw));
    return key;
  }

  public static async encrypt(algorithm: types.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cipher(algorithm, key, data, true);
  }

  public static async decrypt(algorithm: types.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cipher(algorithm, key, data, false);
  }

  private static async cipher(algorithm: types.DesParams, key: DesCryptoKey, data: ArrayBuffer, encrypt: boolean): Promise<ArrayBuffer> {
    this.checkLib();

    const type = encrypt ? "encrypt" : "decrypt";
    let DesCipher: des.Cipher;
    const iv = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.iv);
    switch (algorithm.name.toUpperCase()) {
      case "DES-CBC":
        DesCipher = des.CBC.instantiate(des.DES).create({
          key: key.raw,
          type,
          iv,
        });
        break;
      case "DES-EDE3-CBC":
        DesCipher = des.CBC.instantiate(des.EDE).create({
          key: key.raw,
          type,
          iv,
        });
        break;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
    const enc = DesCipher.update(new Uint8Array(data)).concat(DesCipher.final());
    return new Uint8Array(enc).buffer;
  }

}
