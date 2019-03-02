import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesKwProvider extends core.AesKwProvider {

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages,
    );
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.importKey(format, keyData, { name: algorithm.name }, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(algorithm, key, new Uint8Array(data));
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not a AesCryptoKey");
    }
  }
}
