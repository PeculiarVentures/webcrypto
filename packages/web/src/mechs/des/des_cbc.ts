import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export class DesCbcProvider extends core.DesProvider {

  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-CBC";

  public async onGenerateKey(algorithm: types.DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<DesCryptoKey> {
    return DesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: types.KeyFormat, key: DesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return DesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.DesImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<DesCryptoKey> {
    return DesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: types.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.encrypt(algorithm, key, data);
  }

  public async onDecrypt(algorithm: types.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.decrypt(algorithm, key, data);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is DesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    DesCrypto.checkCryptoKey(key);
  }

}
