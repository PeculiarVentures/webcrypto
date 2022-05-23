import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { BaseCryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

export abstract class EllipticProvider extends ProviderCrypto {

  public abstract namedCurves: string[];

  public override checkGenerateKeyParams(algorithm: types.EcKeyGenParams) {
    // named curve
    this.checkRequiredProperty(algorithm, "namedCurve");
    this.checkNamedCurve(algorithm.namedCurve);
  }

  public checkNamedCurve(namedCurve: string) {
    for (const item of this.namedCurves) {
      if (item.toLowerCase() === namedCurve.toLowerCase()) {
        return;
      }
    }
    throw new OperationError(`namedCurve: Must be one of ${this.namedCurves.join(", ")}`);
  }

  public abstract override onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair>;
  public abstract override onExportKey(format: types.KeyFormat, key: BaseCryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<BaseCryptoKey>;

}
