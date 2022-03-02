import * as core from "webcrypto-core";
import { ShaCrypto } from "./crypto";

export class Sha1Provider extends core.ProviderCrypto {
  public name = "SHA-1";
  public usages = [];

  public override async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
