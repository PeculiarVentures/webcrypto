import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../keys";
import { setCryptoKey, getCryptoKey } from "../storage";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesEde3CbcParams = core.DesParams;

export class DesEde3CbcProvider extends core.DesProvider {

  public keySizeBits = 192;
  public ivSize = 8;
  public name = "DES-EDE3-CBC";

  public async onGenerateKey(algorithm: core.DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await DesCrypto.generateKey(
      {
        name: this.name,
        length: this.keySizeBits,
      },
      extractable,
      keyUsages);

    return setCryptoKey(key);
  }

  public async onEncrypt(algorithm: DesEde3CbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.encrypt(algorithm, getCryptoKey(key) as DesCryptoKey, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: DesEde3CbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.decrypt(algorithm, getCryptoKey(key) as DesCryptoKey, new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return DesCrypto.exportKey(format, getCryptoKey(key) as DesCryptoKey);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await DesCrypto.importKey(format, keyData, { name: this.name, length: this.keySizeBits }, extractable, keyUsages);
    if (key.data.length !== (this.keySizeBits >> 3)) {
      throw new core.OperationError("keyData: Wrong key size");
    }
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof DesCryptoKey)) {
      throw new TypeError("key: Is not a DesCryptoKey");
    }
  }

}
