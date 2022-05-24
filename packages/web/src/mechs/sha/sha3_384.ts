import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { hash384 } from "@stablelib/sha3";

export class Sha3384Provider extends core.ProviderCrypto {
  public name = "SHA3-384";
  public usages: types.ProviderKeyUsage = [];

  public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash384(new Uint8Array(data)).buffer;
  }

}
