import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { AesProvider } from "./base";

export abstract class AesCtrProvider extends AesProvider {

  public readonly name = "AES-CTR";

  public usages: types.KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public override checkAlgorithmParams(algorithm: types.AesCtrParams) {
    // counter
    this.checkRequiredProperty(algorithm, "counter");
    if (!(algorithm.counter instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.counter))) {
      throw new TypeError("counter: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.counter.byteLength !== 16) {
      throw new TypeError("iv: Must have length 16 bytes");
    }
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (algorithm.length < 1) {
      throw new OperationError("length: Must be more than 0");
    }
  }

  public abstract override onEncrypt(algorithm: types.AesCtrParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: types.AesCtrParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
