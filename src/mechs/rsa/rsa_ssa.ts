import * as core from "webcrypto-core";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";
import { setCryptoKey, getCryptoKey } from "../storage";

export class RsaSsaProvider extends core.RsaSsaProvider {

  public override hashAlgorithms = [
    "SHA-1", "SHA-256", "SHA-384", "SHA-512", 
    "shake128", "shake256", 
    "SHA3-256", "SHA3-384", "SHA3-512"];

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<globalThis.CryptoKeyPair> {
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

  public async onSign(algorithm: Algorithm, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.sign(algorithm, getCryptoKey(key) as RsaPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: Algorithm, key: RsaPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return RsaCrypto.verify(algorithm, getCryptoKey(key) as RsaPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, {...algorithm, name: this.name}, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof RsaPrivateKey || internalKey instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

}
