import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { ShaCrypto } from "./crypto";

export class Sha3384Provider extends core.ProviderCrypto {
  public name = "SHA3-384";
  public usages = [];

  public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(algorithm, data);
  }

}
