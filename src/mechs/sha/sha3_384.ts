import * as core from "webcrypto-core";
import { ShaCrypto } from "./crypto";

export class Sha3384Provider extends core.ProviderCrypto {
  public name = "SHA3-384";
  public usages = [];

  public override async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
