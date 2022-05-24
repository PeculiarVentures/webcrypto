import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { hash256 } from "@stablelib/sha3";

export class Sha3256Provider extends core.ProviderCrypto {
  public name = "SHA3-256";
  public usages: types.ProviderKeyUsage = [];

  public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash256(new Uint8Array(data)).buffer;
  }

}
