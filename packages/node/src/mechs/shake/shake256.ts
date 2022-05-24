import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { ShakeCrypto } from "./crypto";

export class Shake256Provider extends core.Shake256Provider {

  public override async onDigest(algorithm: Required<types.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
