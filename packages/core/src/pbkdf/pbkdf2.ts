import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

export abstract class Pbkdf2Provider extends ProviderCrypto {

  public name = "PBKDF2";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: types.KeyUsages = ["deriveBits", "deriveKey"];

  public override checkAlgorithmParams(algorithm: types.Pbkdf2Params) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);

    // salt
    this.checkRequiredProperty(algorithm, "salt");
    if (!(algorithm.salt instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.salt))) {
      throw new TypeError("salt: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }

    // iterations
    this.checkRequiredProperty(algorithm, "iterations");
    if (typeof algorithm.iterations !== "number") {
      throw new TypeError("iterations: Is not a Number");
    }
    if (algorithm.iterations < 1) {
      throw new TypeError("iterations: Is less than 1");
    }
  }

  public override checkImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]) {
    super.checkImportKey(format, keyData, algorithm, extractable, keyUsages);
    if (extractable) {
      // If extractable is not false, then throw a SyntaxError
      throw new SyntaxError("extractable: Must be 'false'");
    }
  }

  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onDeriveBits(algorithm: types.Pbkdf2Params, baseKey: CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;

}
