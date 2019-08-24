import * as crypto from "crypto";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export type RsaPkcs1Params = Algorithm;
export type RsaPkcs1SignParams = core.HashedAlgorithm;

export class RsaPkcs1Provider extends core.ProviderCrypto {

  public name = "RSA-PKCS1";
  public usages = {
    publicKey: ["encrypt", "wrapKey", "verify"] as core.KeyUsages,
    privateKey: ["decrypt", "unwrapKey", "sign"] as core.KeyUsages,
  };
  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public async onGenerateKey(algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return key;
  }

  public checkGenerateKeyParams(algorithm: RsaKeyGenParams) {
    // public exponent
    this.checkRequiredProperty(algorithm, "publicExponent");
    if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
      throw new TypeError("publicExponent: Missing or not a Uint8Array");
    }
    const publicExponent = Convert.ToBase64(algorithm.publicExponent);
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

  public async onSign(algorithm: RsaPkcs1SignParams, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const signature = crypto
      .createSign((algorithm.hash as Algorithm).name.replace("-", ""))
      .update(Buffer.from(data))
      .sign(this.toCryptoOptions(key) as any);
    return new Uint8Array(signature).buffer;
  }

  public checkSign(algorithm: RsaPkcs1SignParams, key: CryptoKey, data: ArrayBuffer) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmSignParams(algorithm);
    this.checkCryptoKey(key, "sign");
  }

  public checkAlgorithmSignParams(algorithm: RsaPkcs1SignParams) {
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as Algorithm, this.hashAlgorithms);
  }

  public async onVerify(algorithm: RsaPkcs1SignParams, key: RsaPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const ok = crypto
      .createVerify((algorithm.hash as Algorithm).name.replace("-", ""))
      .update(Buffer.from(data))
      .verify(this.toCryptoOptions(key) as any, Buffer.from(signature));
    return ok;
  }

  public checkVerify(algorithm: RsaPkcs1SignParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer) {
    this.checkAlgorithmName(algorithm);
    this.checkAlgorithmSignParams(algorithm);
    this.checkCryptoKey(key, "verify");
  }

  public async onEncrypt(algorithm: RsaPkcs1Params, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const enc = crypto.publicEncrypt(options, new Uint8Array(data));
    return new Uint8Array(enc).buffer;
  }

  public async onDecrypt(algorithm: RsaPkcs1Params, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const dec = crypto.privateDecrypt(options, new Uint8Array(data));
    return new Uint8Array(dec).buffer;
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaPrivateKey || key instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

  private toCryptoOptions(key: RsaPrivateKey): crypto.RsaPrivateKey;
  private toCryptoOptions(key: RsaPublicKey): crypto.RsaPublicKey;
  private toCryptoOptions(key: RsaPrivateKey | RsaPublicKey) {
    const type = key.type.toUpperCase();
    return {
      key: `-----BEGIN ${type} KEY-----\n${key.data.toString("base64")}\n-----END ${type} KEY-----`,
      // @ts-ignore
      padding: crypto.constants.RSA_PKCS1_PADDING,
    };
  }

  private prepareSignData(algorithm: RsaPkcs1SignParams, data: ArrayBuffer) {
    return crypto
      .createHash((algorithm.hash as Algorithm).name.replace("-", ""))
      .update(Buffer.from(data))
      .digest();
  }
}
