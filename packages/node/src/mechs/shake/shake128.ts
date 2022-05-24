import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { ShakeCrypto } from "./crypto";

export class Shake128Provider extends core.Shake128Provider {

  public override async onDigest(algorithm: Required<types.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
