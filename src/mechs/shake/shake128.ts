import * as core from "webcrypto-core";
import { ShakeCrypto } from "./crypto";

export class Shake128Provider extends core.ProviderCrypto {
  public name = "shake128";
  public usages = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
