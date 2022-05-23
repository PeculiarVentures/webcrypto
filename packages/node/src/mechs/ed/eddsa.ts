import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../keys";
import { getCryptoKey, setCryptoKey } from "../storage";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdDsaProvider extends core.EdDsaProvider {

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
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

  public async onSign(algorithm: types.EcdsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EdCrypto.sign(algorithm, getCryptoKey(key) as EdPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: types.EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EdCrypto.verify(algorithm, getCryptoKey(key) as EdPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: CryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return EdCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

}