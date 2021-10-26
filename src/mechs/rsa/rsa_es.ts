import * as crypto from "crypto";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { setCryptoKey, getCryptoKey } from "../storage";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaEsProvider extends core.ProviderCrypto {

  public name = "RSAES-PKCS1-v1_5";
  public usages = {
    publicKey: ["encrypt", "wrapKey"] as core.KeyUsages,
    privateKey: ["decrypt", "unwrapKey"] as core.KeyUsages,
  };

  public async onGenerateKey(algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKeyPair> {
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

  public async onEncrypt(algorithm: Algorithm, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const enc = crypto.publicEncrypt(options, new Uint8Array(data));
    return new Uint8Array(enc).buffer;
  }

  public async onDecrypt(algorithm: Algorithm, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const dec = crypto.privateDecrypt(options, new Uint8Array(data));
    return new Uint8Array(dec).buffer;
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof RsaPrivateKey || internalKey instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

  private toCryptoOptions(key: RsaPrivateKey): crypto.RsaPrivateKey;
  private toCryptoOptions(key: RsaPublicKey): crypto.RsaPublicKey;
  private toCryptoOptions(key: RsaPrivateKey | RsaPublicKey) {
    const type = key.type.toUpperCase();
    return {
      key: `-----BEGIN ${type} KEY-----\n${getCryptoKey(key).data.toString("base64")}\n-----END ${type} KEY-----`,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    };
  }
}
