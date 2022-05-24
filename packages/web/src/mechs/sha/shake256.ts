import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { SHAKE256 } from "@stablelib/sha3";

export class Shake256Provider extends core.Shake256Provider {

  public async onDigest(algorithm: Required<types.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    const output = new Uint8Array(algorithm.length);
    new SHAKE256().update(new Uint8Array(data)).stream(output);

    return output.buffer;
  }

}
