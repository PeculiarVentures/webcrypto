import * as types from "@peculiar/webcrypto-types";
import { BufferSourceConverter } from "pvtsutils";
import { AlgorithmError, CryptoError, OperationError, RequiredPropertyError, UnsupportedOperationError } from "./errors";
import { isJWK } from "./utils";

export interface IProviderCheckOptions {
  keyUsage?: boolean;
}

export abstract class ProviderCrypto {

  /**
   * Name of the algorithm
   */
  public abstract readonly name: string;

  /**
   * Key usages for secret key or key pair
   */
  public abstract readonly usages: types.ProviderKeyUsages;

  //#region Digest
  public async digest(algorithm: types.Algorithm, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public async digest(...args: any[]): Promise<ArrayBuffer> {
    this.checkDigest.apply(this, args as unknown as any);
    return this.onDigest.apply(this, args as unknown as any);
  }
  public checkDigest(algorithm: types.Algorithm, data: ArrayBuffer) {
    this.checkAlgorithmName(algorithm);
  }
  public async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new UnsupportedOperationError("digest");
  }
  //#endregion

  //#region Generate key
  public async generateKey(algorithm: types.RsaHashedKeyGenParams | types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair>;
  public async generateKey(algorithm: types.AesKeyGenParams | types.HmacKeyGenParams | types.Pbkdf2Params, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKey>;
  public async generateKey(algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair | types.CryptoKey>;
  public async generateKey(...args: any[]): Promise<types.CryptoKeyPair | types.CryptoKey> {
    this.checkGenerateKey.apply(this, args as unknown as any);
    return this.onGenerateKey.apply(this, args as unknown as any);
  }
  public checkGenerateKey(algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkGenerateKeyParams(algorithm);
    if (!(keyUsages && keyUsages.length)) {
      throw new TypeError(`Usages cannot be empty when creating a key.`);
    }
    let allowedUsages: types.KeyUsages;
    if (Array.isArray(this.usages)) {
      allowedUsages = this.usages;
    } else {
      allowedUsages = this.usages.privateKey.concat(this.usages.publicKey);
    }
    this.checkKeyUsages(keyUsages, allowedUsages);
  }
  public checkGenerateKeyParams(algorithm: types.Algorithm) {
    // nothing
  }
  public async onGenerateKey(algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair | types.CryptoKey> {
    throw new UnsupportedOperationError("generateKey");
  }
  //#endregion

  //#region Sign
  public async sign(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public async sign(...args: any[]): Promise<ArrayBuffer> {
    this.checkSign.apply(this, args as unknown as any);
    return this.onSign.apply(this, args as unknown as any);
  }
  public checkSign(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmParams(algorithm);
    this.checkCryptoKey(key, "sign");
  }
  public async onSign(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
    throw new UnsupportedOperationError("sign");
  }
  //#endregion

  //#region Verify
  public async verify(algorithm: types.Algorithm, key: types.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;
  public async verify(...args: any[]): Promise<boolean> {
    this.checkVerify.apply(this, args as unknown as any);
    return this.onVerify.apply(this, args as unknown as any);
  }
  public checkVerify(algorithm: types.Algorithm, key: types.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmParams(algorithm);
    this.checkCryptoKey(key, "verify");
  }
  public async onVerify(algorithm: types.Algorithm, key: types.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean> {
    throw new UnsupportedOperationError("verify");
  }
  //#endregion

  //#region Encrypt
  public async encrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, options?: IProviderCheckOptions, ...args: any[]): Promise<ArrayBuffer>;
  public async encrypt(...args: any[]): Promise<ArrayBuffer> {
    this.checkEncrypt.apply(this, args as unknown as any);
    return this.onEncrypt.apply(this, args as unknown as any);
  }
  public checkEncrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, options: IProviderCheckOptions = {}, ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmParams(algorithm);
    this.checkCryptoKey(key, options.keyUsage ? "encrypt" : void 0);
  }
  public async onEncrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
    throw new UnsupportedOperationError("encrypt");
  }
  //#endregion

  //#region Decrypt
  public async decrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, options?: IProviderCheckOptions, ...args: any[]): Promise<ArrayBuffer>;
  public async decrypt(...args: any[]): Promise<ArrayBuffer> {
    this.checkDecrypt.apply(this, args as unknown as any);
    return this.onDecrypt.apply(this, args as unknown as any);
  }
  public checkDecrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, options: IProviderCheckOptions = {}, ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmParams(algorithm);
    this.checkCryptoKey(key, options.keyUsage ? "decrypt" : void 0);
  }
  public async onDecrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
    throw new UnsupportedOperationError("decrypt");
  }
  //#endregion

  //#region Derive bits
  public async deriveBits(algorithm: types.Algorithm, baseKey: types.CryptoKey, length: number, options?: IProviderCheckOptions, ...args: any[]): Promise<ArrayBuffer>;
  public async deriveBits(...args: any[]): Promise<ArrayBuffer> {
    this.checkDeriveBits.apply(this, args as unknown as any);
    return this.onDeriveBits.apply(this, args as unknown as any);
  }
  public checkDeriveBits(algorithm: types.Algorithm, baseKey: types.CryptoKey, length: number, options: IProviderCheckOptions = {}, ...args: any[]) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmParams(algorithm);
    this.checkCryptoKey(baseKey, options.keyUsage ? "deriveBits" : void 0);
    if (length % 8 !== 0) {
      throw new OperationError("length: Is not multiple of 8");
    }
  }
  public async onDeriveBits(algorithm: types.Algorithm, baseKey: types.CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer> {
    throw new UnsupportedOperationError("deriveBits");
  }
  //#endregion

  //#region Export key
  public async exportKey(format: types.KeyFormat, key: types.CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public async exportKey(...args: any[]): Promise<types.JsonWebKey | ArrayBuffer> {
    this.checkExportKey.apply(this, args as unknown as any);
    return this.onExportKey.apply(this, args as unknown as any);
  }
  public checkExportKey(format: types.KeyFormat, key: types.CryptoKey, ...args: any[]) {
    this.checkKeyFormat(format);
    this.checkCryptoKey(key);

    if (!key.extractable) {
      throw new CryptoError("key: Is not extractable");
    }
  }
  public async onExportKey(format: types.KeyFormat, key: types.CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer> {
    throw new UnsupportedOperationError("exportKey");
  }
  //#endregion

  //#region Import key
  public async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey>;
  public async importKey(...args: any[]): Promise<types.CryptoKey> {
    this.checkImportKey.apply(this, args as unknown as any);
    return this.onImportKey.apply(this, args as unknown as any);
  }
  public checkImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]) {
    this.checkKeyFormat(format);
    this.checkKeyData(format, keyData);
    this.checkAlgorithmName(algorithm);
    this.checkImportParams(algorithm);

    // check key usages
    if (Array.isArray(this.usages)) {
      // symmetric provider
      this.checkKeyUsages(keyUsages, this.usages);
    } else {
      // asymmetric provider
      // TODO: implement
    }
  }
  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey> {
    throw new UnsupportedOperationError("importKey");
  }
  //#endregion

  public checkAlgorithmName(algorithm: types.Algorithm) {
    if (algorithm.name.toLowerCase() !== this.name.toLowerCase()) {
      throw new AlgorithmError("Unrecognized name");
    }
  }

  public checkAlgorithmParams(algorithm: types.Algorithm) {
    // nothing
  }

  public checkDerivedKeyParams(algorithm: types.Algorithm) {
    // nothing
  }

  public checkKeyUsages(usages: types.KeyUsages, allowed: types.KeyUsages) {
    for (const usage of usages) {
      if (allowed.indexOf(usage) === -1) {
        throw new TypeError("Cannot create a key using the specified key usages");
      }
    }
  }

  public checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
    this.checkAlgorithmName(key.algorithm);
    if (keyUsage && key.usages.indexOf(keyUsage) === -1) {
      throw new CryptoError(`key does not match that of operation`);
    }
  }

  public checkRequiredProperty(data: object, propName: string) {
    if (!(propName in data)) {
      throw new RequiredPropertyError(propName);
    }
  }

  public checkHashAlgorithm(algorithm: types.Algorithm, hashAlgorithms: string[]) {
    for (const item of hashAlgorithms) {
      if (item.toLowerCase() === algorithm.name.toLowerCase()) {
        return;
      }
    }
    throw new OperationError(`hash: Must be one of ${hashAlgorithms.join(", ")}`);
  }

  public checkImportParams(algorithm: types.Algorithm) {
    // nothing
  }

  public checkKeyFormat(format: any) {
    switch (format) {
      case "raw":
      case "pkcs8":
      case "spki":
      case "jwk":
        break;
      default:
        throw new TypeError("format: Is invalid value. Must be 'jwk', 'raw', 'spki', or 'pkcs8'");
    }
  }

  public checkKeyData(format: types.KeyFormat, keyData: any) {
    if (!keyData) {
      throw new TypeError("keyData: Cannot be empty on empty on key importing");
    }
    if (format === "jwk") {
      if (!isJWK(keyData)) {
        throw new TypeError("keyData: Is not JsonWebToken");
      }
    } else if (!BufferSourceConverter.isBufferSource(keyData)) {
      throw new TypeError("keyData: Is not ArrayBufferView or ArrayBuffer");
    }
  }

  protected prepareData(data: any) {
    return BufferSourceConverter.toArrayBuffer(data);
  }
}
