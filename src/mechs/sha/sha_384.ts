import * as core from "webcrypto-core";
import { ShaCrypto } from "./crypto";

export class Sha384Provider extends core.ProviderCrypto {
  public name = "SHA-384";
  public usages = [];

  public override async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
