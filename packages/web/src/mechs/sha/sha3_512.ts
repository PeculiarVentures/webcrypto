import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { hash512 } from "@stablelib/sha3";

export class Sha3512Provider extends core.ProviderCrypto {
  public name = "SHA3-512";
  public usages: types.ProviderKeyUsage = [];

  public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash512(new Uint8Array(data)).buffer;
  }

}
