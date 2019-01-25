import * as core from "webcrypto-core";
import { ShaCrypto } from "./crypto";

export class Sha512Provider extends core.ProviderCrypto {
  public name = "SHA-512";
  public usages = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
