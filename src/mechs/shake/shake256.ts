import * as core from "webcrypto-core";
import { ShakeCrypto } from "./crypto";

export class Shake256Provider extends core.ProviderCrypto {
  public name = "shake256";
  public usages = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
