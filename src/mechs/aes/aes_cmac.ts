import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCmacProvider extends core.AesCmacProvider {

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const key = await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: AesCmacParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("CMAC sign method is not implemented");
  }

  public async onVerify(algorithm: AesCmacParams, key: AesCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    throw new Error("CMAC verify method is not implemented");
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
