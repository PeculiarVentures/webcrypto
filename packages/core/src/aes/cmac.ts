import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { AesProvider } from "./base";

export abstract class AesCmacProvider extends AesProvider {

  public readonly name = "AES-CMAC";

  public usages: types.KeyUsages = ["sign", "verify"];

  public override checkAlgorithmParams(algorithm: types.AesCmacParams) {
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (algorithm.length < 1) {
      throw new OperationError("length: Must be more than 0");
    }
  }

  public abstract override onSign(algorithm: types.AesCmacParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onVerify(algorithm: types.AesCmacParams, key: types.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;

}
