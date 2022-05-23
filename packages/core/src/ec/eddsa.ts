import { CryptoKey, EcdsaParams, ProviderKeyUsages } from "@peculiar/webcrypto-types";
import { EllipticProvider } from "./base";

export abstract class EdDsaProvider extends EllipticProvider {

  public readonly name: string = "EdDSA";

  public usages: ProviderKeyUsages = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };

  public namedCurves = ["Ed25519", "Ed448"];

  public abstract override onSign(algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onVerify(algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean>;

}
