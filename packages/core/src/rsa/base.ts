import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { BaseCryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

export abstract class RsaProvider extends ProviderCrypto {

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public override checkGenerateKeyParams(algorithm: types.RsaHashedKeyGenParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);

    // public exponent
    this.checkRequiredProperty(algorithm, "publicExponent");
    if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
      throw new TypeError("publicExponent: Missing or not a Uint8Array");
    }
    const publicExponent = Convert.ToBase64(algorithm.publicExponent);
    if (!(publicExponent === "Aw==" || publicExponent === "AQAB")) {
      throw new TypeError("publicExponent: Must be [3] or [1,0,1]");
    }

    // modulus length
    this.checkRequiredProperty(algorithm, "modulusLength");
    if (algorithm.modulusLength % 8
      || algorithm.modulusLength < 256
      || algorithm.modulusLength > 16384) {
      throw new TypeError("The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
    }
  }

  public override checkImportParams(algorithm: types.RsaHashedImportParams) {
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);
  }

  public abstract override onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair>;
  public abstract override onExportKey(format: types.KeyFormat, key: BaseCryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<BaseCryptoKey>;

}
