import crypto from "crypto";
import * as core from "webcrypto-core";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";
import { ShaCrypto } from "../sha/crypto";
import { setCryptoKey, getCryptoKey } from "../storage";

/**
 * Source code for decrypt, encrypt, mgf1 functions is from asmcrypto module
 * https://github.com/asmcrypto/asmcrypto.js/blob/master/src/rsa/pkcs1.ts
 *
 * This code can be removed after https://github.com/nodejs/help/issues/1726 fixed
 */

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

      return {
        privateKey: setCryptoKey(keys.privateKey as RsaPrivateKey),
        publicKey: setCryptoKey(keys.publicKey as RsaPublicKey),
      };
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const internalKey = getCryptoKey(key) as RsaPublicKey;
    const dataView = new Uint8Array(data);
    const keySize = Math.ceil(internalKey.algorithm.modulusLength >> 3);
    const hashSize = ShaCrypto.size(internalKey.algorithm.hash) >> 3;
    const dataLength = dataView.byteLength;
    const psLength = keySize - dataLength - 2 * hashSize - 2;

    if (dataLength > keySize - 2 * hashSize - 2) {
      throw new Error("Data too large");
    }

    const message = new Uint8Array(keySize);
    const seed = message.subarray(1, hashSize + 1);
    const dataBlock = message.subarray(hashSize + 1);

    dataBlock.set(dataView, hashSize + psLength + 1);

    const labelHash = crypto.createHash(internalKey.algorithm.hash.name.replace("-", ""))
      .update(core.BufferSourceConverter.toUint8Array(algorithm.label || new Uint8Array(0)))
      .digest();
    dataBlock.set(labelHash, 0);
    dataBlock[hashSize + psLength] = 1;

    crypto.randomFillSync(seed);

    const dataBlockMask = this.mgf1(internalKey.algorithm.hash, seed, dataBlock.length);
    for (let i = 0; i < dataBlock.length; i++) {
      dataBlock[i] ^= dataBlockMask[i];
    }

    const seedMask = this.mgf1(internalKey.algorithm.hash, dataBlock, seed.length);
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i];
    }

    if (!internalKey.pem) {
      internalKey.pem = `-----BEGIN PUBLIC KEY-----\n${internalKey.data.toString("base64")}\n-----END PUBLIC KEY-----`;
    }

    const pkcs0 = crypto.publicEncrypt({
      key: internalKey.pem,
      padding: crypto.constants.RSA_NO_PADDING,
    }, Buffer.from(message));

    return new Uint8Array(pkcs0).buffer;
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const internalKey = getCryptoKey(key) as RsaPrivateKey;
    const keySize = Math.ceil(internalKey.algorithm.modulusLength >> 3);
    const hashSize = ShaCrypto.size(internalKey.algorithm.hash) >> 3;
    const dataLength = data.byteLength;

    if (dataLength !== keySize) {
      throw new Error("Bad data");
    }

    if (!internalKey.pem) {
      internalKey.pem = `-----BEGIN PRIVATE KEY-----\n${internalKey.data.toString("base64")}\n-----END PRIVATE KEY-----`;
    }

    let pkcs0 = crypto.privateDecrypt({
      key: internalKey.pem,
      padding: crypto.constants.RSA_NO_PADDING,
    }, Buffer.from(data));
    const z = pkcs0[0];
    const seed = pkcs0.subarray(1, hashSize + 1);
    const dataBlock = pkcs0.subarray(hashSize + 1);

    if (z !== 0) {
      throw new Error("Decryption failed");
    }

    const seedMask = this.mgf1(internalKey.algorithm.hash, dataBlock, seed.length);
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i];
    }

    const dataBlockMask = this.mgf1(internalKey.algorithm.hash, seed, dataBlock.length);
    for (let i = 0; i < dataBlock.length; i++) {
      dataBlock[i] ^= dataBlockMask[i];
    }

    const labelHash = crypto.createHash(internalKey.algorithm.hash.name.replace("-", ""))
      .update(core.BufferSourceConverter.toUint8Array(algorithm.label || new Uint8Array(0)))
      .digest();
    for (let i = 0; i < hashSize; i++) {
      if (labelHash[i] !== dataBlock[i]) {
        throw new Error("Decryption failed");
      }
    }

    let psEnd = hashSize;
    for (; psEnd < dataBlock.length; psEnd++) {
      const psz = dataBlock[psEnd];
      if (psz === 1) {
        break;
      }
      if (psz !== 0) {
        throw new Error("Decryption failed");
      }
    }
    if (psEnd === dataBlock.length) {
      throw new Error("Decryption failed");
    }

    pkcs0 = dataBlock.subarray(psEnd + 1);

    return new Uint8Array(pkcs0).buffer;
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof RsaPrivateKey || internalKey instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

  /**
   * RSA MGF1
   * @param algorithm Hash algorithm
   * @param seed
   * @param length
   */
  protected mgf1(algorithm: Algorithm, seed: Uint8Array, length = 0) {
    const hashSize = ShaCrypto.size(algorithm) >> 3;
    const mask = new Uint8Array(length);
    const counter = new Uint8Array(4);
    const chunks = Math.ceil(length / hashSize);
    for (let i = 0; i < chunks; i++) {
      counter[0] = i >>> 24;
      counter[1] = (i >>> 16) & 255;
      counter[2] = (i >>> 8) & 255;
      counter[3] = i & 255;

      const submask = mask.subarray(i * hashSize);

      let chunk = crypto.createHash(algorithm.name.replace("-", ""))
        .update(seed)
        .update(counter)
        .digest() as Uint8Array;
      if (chunk.length > submask.length) {
        chunk = chunk.subarray(0, submask.length);
      }

      submask.set(chunk);
    }

    return mask;
  }

}
