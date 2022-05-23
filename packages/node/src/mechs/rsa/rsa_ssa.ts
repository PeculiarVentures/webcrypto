import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { setCryptoKey, getCryptoKey } from "../storage";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaSsaProvider extends core.RsaSsaProvider {

  public override hashAlgorithms = [
    "SHA-1", "SHA-256", "SHA-384", "SHA-512",
    "shake128", "shake256",
    "SHA3-256", "SHA3-384", "SHA3-512"];

  public async onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
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

  public async onSign(algorithm: types.Algorithm, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.sign(algorithm, getCryptoKey(key) as RsaPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: types.Algorithm, key: RsaPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return RsaCrypto.verify(algorithm, getCryptoKey(key) as RsaPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: types.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
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

}
