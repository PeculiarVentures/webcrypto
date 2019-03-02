import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { EcCrypto } from "./crypto";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcdhProvider extends core.EcdhProvider {

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await EcCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await EcCrypto.importKey(format, keyData, {...algorithm, name: this.name}, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcPrivateKey || key instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    const bits = await EcCrypto.deriveBits(algorithm, baseKey, length);
    return bits;
  }

}
