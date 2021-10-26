import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { getCryptoKey, setCryptoKey } from "../storage";
import { EdCrypto } from "./crypto";

export class EcdhEsProvider extends core.EcdhEsProvider {
  
  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.toUpperCase(),
      },
      extractable,
      keyUsages);

    return {
      privateKey: setCryptoKey(keys.privateKey as CryptoKey),
      publicKey: setCryptoKey(keys.publicKey as CryptoKey),
    };
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: core.CryptoKey, length: number): Promise<ArrayBuffer> {
    const bits = await EdCrypto.deriveBits({...algorithm, public: getCryptoKey(algorithm.public)}, getCryptoKey(baseKey), length);
    return bits;
  }
  
  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return EdCrypto.exportKey(format, getCryptoKey(key));
  }
  
  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

}