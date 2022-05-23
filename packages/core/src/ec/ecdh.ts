import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { CryptoKey } from "../crypto_key";
import { EllipticProvider } from "./base";

export abstract class EcdhProvider extends EllipticProvider {

  public readonly name: string = "ECDH";

  public usages: types.ProviderKeyUsages = {
    privateKey: ["deriveBits", "deriveKey"],
    publicKey: [],
  };

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  public override checkAlgorithmParams(algorithm: types.EcdhKeyDeriveParams) {
    // public
    this.checkRequiredProperty(algorithm, "public");
    if (!(algorithm.public instanceof CryptoKey)) {
      throw new TypeError("public: Is not a CryptoKey");
    }
    if (algorithm.public.type !== "public") {
      throw new OperationError("public: Is not a public key");
    }
    if (algorithm.public.algorithm.name !== this.name) {
      throw new OperationError(`public: Is not ${this.name} key`);
    }
  }

  public abstract override onDeriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;

}
