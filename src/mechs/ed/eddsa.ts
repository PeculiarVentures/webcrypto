import * as core from "webcrypto-core";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";
import { CryptoKey } from "../../keys";
import { getCryptoKey, setCryptoKey } from "../storage";

export class EdDsaProvider extends core.EdDsaProvider {

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.replace(/^ed/i, "Ed"),
      },
      extractable,
      keyUsages);

    return {
      privateKey: setCryptoKey(keys.privateKey as CryptoKey),
      publicKey: setCryptoKey(keys.publicKey as CryptoKey),
    };
  }

  public async onSign(algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EdCrypto.sign(algorithm, getCryptoKey(key) as EdPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EdCrypto.verify(algorithm, getCryptoKey(key) as EdPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return EdCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

}