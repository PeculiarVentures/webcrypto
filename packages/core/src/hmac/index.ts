import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

export abstract class HmacProvider extends ProviderCrypto {

  public name = "HMAC";

  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public usages: types.KeyUsages = ["sign", "verify"];

  /**
   * Returns default size in bits by hash algorithm name
   * @param algName Name of the hash algorithm
   */
  public getDefaultLength(algName: string) {
    switch (algName.toUpperCase()) {
      // Chrome, Safari and Firefox returns 512
      case "SHA-1":
      case "SHA-256":
      case "SHA-384":
      case "SHA-512":
        return 512;
      default:
        throw new Error(`Unknown algorithm name '${algName}'`);
    }
  }

  public override checkGenerateKeyParams(algorithm: types.HmacKeyGenParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);

    // length
    if ("length" in algorithm) {
      if (typeof algorithm.length !== "number") {
        throw new TypeError("length: Is not a Number");
      }
      if (algorithm.length < 1) {
        throw new RangeError("length: Number is out of range");
      }
    }
  }

  public override checkImportParams(algorithm: types.HmacImportParams) {
    // hash
    this.checkRequiredProperty(algorithm, "hash");
    this.checkHashAlgorithm(algorithm.hash as types.Algorithm, this.hashAlgorithms);
  }

  public abstract override onGenerateKey(algorithm: types.PreparedHashedAlgorithm<types.HmacKeyGenParams>, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: types.KeyFormat, key: CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.HmacImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;

}
