import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesGcmProvider extends core.AesGcmProvider {

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.importKey(format, keyData, { name: algorithm.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not a AesCryptoKey");
    }
  }
}
