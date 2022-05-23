import * as types from "@peculiar/webcrypto-types";
import { BufferSourceConverter } from "pvtsutils";
import { BaseCryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

export abstract class HkdfProvider extends ProviderCrypto {

  public name = "HKDF";
  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
  public usages: types.KeyUsages = ["deriveKey", "deriveBits"];

  public override checkAlgorithmParams(algorithm: types.HkdfParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);

    // salt
    this.checkRequiredProperty(algorithm, "salt");
    if (!BufferSourceConverter.isBufferSource(algorithm.salt)) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }

    // info
    this.checkRequiredProperty(algorithm, "info");
    if (!BufferSourceConverter.isBufferSource(algorithm.info)) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
  }

  public override checkImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]) {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages);
    if (extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be 'false'");
    }
  }

  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<BaseCryptoKey>;
  public abstract override onDeriveBits(algorithm: types.HkdfParams, baseKey: BaseCryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;

}
