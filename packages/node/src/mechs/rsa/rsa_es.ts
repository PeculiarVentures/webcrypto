import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import * as pvtsutils from "pvtsutils";
import { setCryptoKey, getCryptoKey } from "../storage";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaEsProvider extends core.ProviderCrypto {

  public name = "RSAES-PKCS1-v1_5";
  public usages = {
    publicKey: ["encrypt", "wrapKey"] as types.KeyUsages,
    privateKey: ["decrypt", "unwrapKey"] as types.KeyUsages,
  };

  public override async onGenerateKey(algorithm: types.RsaKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
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

  public override async onEncrypt(algorithm: types.Algorithm, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const enc = crypto.publicEncrypt(options, new Uint8Array(data));
    return new Uint8Array(enc).buffer;
  }

  public override async onDecrypt(algorithm: types.Algorithm, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const options = this.toCryptoOptions(key);
    const dec = crypto.privateDecrypt(options, new Uint8Array(data));
    return new Uint8Array(dec).buffer;
  }

  public override async onExportKey(format: types.KeyFormat, key: types.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public override async onImportKey(format: types.KeyFormat, keyData: crypto.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
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
