import * as types from "@peculiar/webcrypto-types";
import { ProviderCrypto } from "../provider";
import { CryptoKey } from "../crypto_key";

export abstract class AesProvider extends ProviderCrypto {

  public override checkGenerateKeyParams(algorithm: types.AesKeyGenParams) {
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    switch (algorithm.length) {
      case 128:
      case 192:
      case 256:
        break;
      default:
        throw new TypeError("length: Must be 128, 192, or 256");
    }
  }

  public override checkDerivedKeyParams(algorithm: types.AesKeyGenParams) {
    this.checkGenerateKeyParams(algorithm);
  }

  public abstract override onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: types.KeyFormat, key: CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;

}
