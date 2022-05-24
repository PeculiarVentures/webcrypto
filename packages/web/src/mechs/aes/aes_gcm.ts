import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesGcmProvider extends core.AesGcmProvider {

  public async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    return AesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: types.AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(algorithm, key, data);
  }

  public async onDecrypt(algorithm: types.AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(algorithm, key, data);
  }

  public async onExportKey(format: types.KeyFormat, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }

}
