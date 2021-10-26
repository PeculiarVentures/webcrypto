import * as core from "webcrypto-core";
import { setCryptoKey, getCryptoKey } from "../storage";
import { EcCrypto } from "./crypto";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcdsaProvider extends core.EcdsaProvider {

  public namedCurves = core.EcCurves.names;

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKeyPair> {
    const keys = await EcCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return {
      privateKey: setCryptoKey(keys.privateKey as EcPrivateKey),
      publicKey: setCryptoKey(keys.publicKey as EcPublicKey),
    };
  }

  public async onSign(algorithm: EcdsaParams, key: EcPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EcCrypto.sign(algorithm, getCryptoKey(key) as EcPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: EcdsaParams, key: EcPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EcCrypto.verify(algorithm, getCryptoKey(key) as EcPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await EcCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof EcPrivateKey || internalKey instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

}
