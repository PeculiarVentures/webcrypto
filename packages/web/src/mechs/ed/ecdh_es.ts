import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../key";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EcdhEsProvider extends core.EcdhEsProvider {

  public override namedCurves: string[] = ["X25519"];

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.replace(/^x/i, "X"),
      },
      extractable,
      keyUsages);

    return keys;
  }

  public async onDeriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: EdPrivateKey, length: number): Promise<ArrayBuffer> {
    const bits = await EdCrypto.deriveBits({ ...algorithm, public: algorithm.public as EdPublicKey }, baseKey, length);
    return bits;
  }

  public async onExportKey(format: types.KeyFormat, key: EdPrivateKey | EdPublicKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return EdCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);

    return key;
  }

}