import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesEde3CbcParams = core.DesParams;

export class DesEde3CbcProvider extends core.DesProvider {

  public keySizeBits = 192;
  public ivSize = 8;
  public name = "DES-EDE3-CBC";

  public async onGenerateKey(algorithm: core.DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const key = await DesCrypto.generateKey(
      {
        name: this.name,
        length: this.keySizeBits,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: DesEde3CbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.encrypt(algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: DesEde3CbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.decrypt(algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return DesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await DesCrypto.importKey(format, keyData, { name: this.name, length: this.keySizeBits }, extractable, keyUsages);
    if (key.data.length !== (this.keySizeBits >> 3)) {
      throw new core.OperationError("keyData: Wrong key size");
    }
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof DesCryptoKey)) {
      throw new TypeError("key: Is not a DesCryptoKey");
    }
  }

}
