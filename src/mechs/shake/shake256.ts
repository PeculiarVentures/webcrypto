import * as core from "webcrypto-core";
import { ShakeCrypto } from "./crypto";

export class Shake256Provider extends core.Shake256Provider {

  public override async onDigest(algorithm: Required<core.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
