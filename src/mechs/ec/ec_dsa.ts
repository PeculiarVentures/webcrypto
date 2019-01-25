import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { EcCrypto } from "./crypto";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcdsaProvider extends core.EcdsaProvider {

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const key = await EcCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: EcdsaParams, key: EcPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EcCrypto.sign(algorithm, key, new Uint8Array(data));
  }

  public async onVerify(algorithm: EcdsaParams, key: EcPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EcCrypto.verify(algorithm, key, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await EcCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcPrivateKey || key instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

}
