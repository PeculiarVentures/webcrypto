import * as core from "webcrypto-core";
import { ShakeCrypto } from "./crypto";

export class Shake128Provider extends core.Shake128Provider {

  public override async onDigest(algorithm: Required<core.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShakeCrypto.digest(algorithm, data);
  }

}
