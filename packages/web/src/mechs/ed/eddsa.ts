import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdDsaProvider extends core.EdDsaProvider {

  public override namedCurves: string[] = ["Ed25519"];

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.replace(/^ed/i, "Ed"),
      },
      extractable,
      keyUsages);

    return keys;
  }

  public async onSign(algorithm: types.EcdsaParams, key: EdPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EdCrypto.sign(algorithm, key, new Uint8Array(data));
  }

  public async onVerify(algorithm: types.EcdsaParams, key: EdPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EdCrypto.verify(algorithm, key, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: EdPrivateKey | EdPublicKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return EdCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

}