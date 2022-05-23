import * as types from "@peculiar/webcrypto-types";
import { AesProvider } from "./base";

export abstract class AesCbcProvider extends AesProvider {

  public readonly name = "AES-CBC";

  public usages: types.KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public override checkAlgorithmParams(algorithm: types.AesCbcParams) {
    this.checkRequiredProperty(algorithm, "iv");
    if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
      throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    if (algorithm.iv.byteLength !== 16) {
      throw new TypeError("iv: Must have length 16 bytes");
    }
  }

  public abstract override onEncrypt(algorithm: types.AesCbcParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: types.AesCbcParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
