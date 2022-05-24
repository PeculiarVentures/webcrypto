import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesEde3CbcParams = types.DesParams;

export class DesEde3CbcProvider extends core.DesProvider {

  public keySizeBits = 192;
  public ivSize = 8;
  public name = "DES-EDE3-CBC";

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

  public override checkCryptoKey(key: DesCryptoKey, keyUsage: types.KeyUsage): asserts key is DesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    DesCrypto.checkCryptoKey(key);
  }

}
