import { ProviderCrypto } from "../provider";
import * as types from "@peculiar/webcrypto-types";

export abstract class ShakeProvider extends ProviderCrypto {

  public usages = [];
  public defaultLength = 0;

  public override digest(algorithm: types.ShakeParams, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public override digest(...args: any[]): Promise<ArrayBuffer> {
    args[0] = { length: this.defaultLength, ...args[0] };

    return super.digest.apply(this, args as unknown as any);
  }

  public override checkDigest(algorithm: types.ShakeParams, data: ArrayBuffer): void {
    super.checkDigest(algorithm, data);

    const length = algorithm.length || 0;
    if (typeof length !== "number") {
      throw new TypeError("length: Is not a Number");
    }
    if (length < 0) {
      throw new TypeError("length: Is negative");
    }
  }

  public abstract override onDigest(algorithm: Required<types.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer>;

}
