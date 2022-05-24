import * as core from "@peculiar/webcrypto-core";
import { AesKeyGenParams, KeyUsage, CryptoKey, AesCbcParams, KeyFormat, JsonWebKey, Algorithm } from "@peculiar/webcrypto-types";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCbcProvider extends core.AesCbcProvider {

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<AesCryptoKey> {
    return AesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: AesCbcParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(algorithm, key, data);
  }

  public async onDecrypt(algorithm: AesCbcParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(algorithm, key, data);
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, key);
  }

  public onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<AesCryptoKey> {
    return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }

}
