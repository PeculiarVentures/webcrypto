import * as core from "webcrypto-core";
import { ShaCrypto } from "./crypto";

export class Sha256Provider extends core.ProviderCrypto {
  public name = "SHA-256";
  public usages = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
