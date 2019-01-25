import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const key = await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.encrypt(algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.decrypt(algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, {...algorithm, name: this.name}, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaPrivateKey || key instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

}
