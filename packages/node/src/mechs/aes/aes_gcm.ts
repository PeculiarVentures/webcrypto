import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { setCryptoKey, getCryptoKey } from "../storage";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesGcmProvider extends core.AesGcmProvider {

  public async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return setCryptoKey(key);
  }

  public async onEncrypt(algorithm: types.AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(algorithm, getCryptoKey(key) as AesCryptoKey, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: types.AesGcmParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(algorithm, getCryptoKey(key) as AesCryptoKey, new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, getCryptoKey(key) as AesCryptoKey);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const res = await AesCrypto.importKey(format, keyData, { name: algorithm.name }, extractable, keyUsages);
    return setCryptoKey(res);
  }

  public override checkCryptoKey(key: core.BaseCryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not a AesCryptoKey");
    }
  }
}