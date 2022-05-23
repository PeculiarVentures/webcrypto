import * as types from "@peculiar/webcrypto-types";
import { AesProvider } from "./base";

export abstract class AesEcbProvider extends AesProvider {

  public readonly name = "AES-ECB";

  public usages: types.KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public abstract override onEncrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
