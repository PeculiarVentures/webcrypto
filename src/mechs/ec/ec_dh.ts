import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { setCryptoKey, getCryptoKey } from "../storage";
import { EcCrypto } from "./crypto";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcdhProvider extends core.EcdhProvider {

  public override namedCurves = core.EcCurves.names;

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await EcCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

    return {
      privateKey: setCryptoKey(keys.privateKey as CryptoKey),
      publicKey: setCryptoKey(keys.publicKey as CryptoKey),
    };
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EcCrypto.importKey(format, keyData, {...algorithm, name: this.name}, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof EcPrivateKey || internalKey instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    const bits = await EcCrypto.deriveBits({...algorithm, public: getCryptoKey(algorithm.public)}, getCryptoKey(baseKey), length);
    return bits;
  }

}
