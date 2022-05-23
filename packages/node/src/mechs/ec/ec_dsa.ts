import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { setCryptoKey, getCryptoKey } from "../storage";
import { EcCrypto } from "./crypto";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcdsaProvider extends core.EcdsaProvider {

  public override namedCurves = core.EcCurves.names;

  public override hashAlgorithms = [
    "SHA-1", "SHA-256", "SHA-384", "SHA-512",
    "shake128", "shake256",
    "SHA3-256", "SHA3-384", "SHA3-512"];

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
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

  public async onSign(algorithm: types.EcdsaParams, key: EcPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EcCrypto.sign(algorithm, getCryptoKey(key) as EcPrivateKey, new Uint8Array(data));
  }

  public async onVerify(algorithm: types.EcdsaParams, key: EcPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EcCrypto.verify(algorithm, getCryptoKey(key) as EcPublicKey, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: types.KeyFormat, key: types.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return EcCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    const key = await EcCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof EcPrivateKey || internalKey instanceof EcPublicKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

}
