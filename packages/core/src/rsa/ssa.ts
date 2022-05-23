import * as types from "@peculiar/webcrypto-types";
import { RsaProvider } from "./base";

export interface RsaSsaParams extends types.Algorithm { }

export abstract class RsaSsaProvider extends RsaProvider {

  public readonly name = "RSASSA-PKCS1-v1_5";

  public usages: types.ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public abstract override onSign(algorithm: RsaSsaParams, key: types.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onVerify(algorithm: RsaSsaParams, key: types.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;

}
