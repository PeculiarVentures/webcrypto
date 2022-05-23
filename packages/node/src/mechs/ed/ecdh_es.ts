import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../keys";
import { getCryptoKey, setCryptoKey } from "../storage";
import { EdCrypto } from "./crypto";

export class EcdhEsProvider extends core.EcdhEsProvider {

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
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

  public async onDeriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: core.BaseCryptoKey, length: number): Promise<ArrayBuffer> {
    const bits = await EdCrypto.deriveBits({ ...algorithm, public: getCryptoKey(algorithm.public) }, getCryptoKey(baseKey), length);
    return bits;
  }

  public async onExportKey(format: types.KeyFormat, key: CryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return EdCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

}