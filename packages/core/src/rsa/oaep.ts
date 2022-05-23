import * as types from "@peculiar/webcrypto-types";
import { RsaProvider } from "./base";

export abstract class RsaOaepProvider extends RsaProvider {

  public readonly name = "RSA-OAEP";

  public usages: types.ProviderKeyUsages = {
    privateKey: ["decrypt", "unwrapKey"],
    publicKey: ["encrypt", "wrapKey"],
  };

  public override checkAlgorithmParams(algorithm: types.RsaOaepParams) {
    // label
    if (algorithm.label
      && !(algorithm.label instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.label))) {
      throw new TypeError("label: Is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
  }

  public abstract override onEncrypt(algorithm: types.RsaOaepParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: types.RsaOaepParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
