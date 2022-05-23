import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../keys";
import { setCryptoKey, getCryptoKey } from "../storage";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesCbcParams = core.DesParams;

export class DesCbcProvider extends core.DesProvider {

  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-CBC";

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

  public async onEncrypt(algorithm: DesCbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.encrypt(algorithm, getCryptoKey(key) as DesCryptoKey, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: DesCbcParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
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
