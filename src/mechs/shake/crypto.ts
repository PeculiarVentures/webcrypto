import crypto from "crypto";
import * as core from "webcrypto-core";

export class ShakeCrypto {

  public static digest(algorithm: Required<core.ShakeParams>, data: ArrayBuffer) {
    const hash = crypto.createHash(algorithm.name.toLowerCase(), {outputLength: algorithm.length})
      .update(Buffer.from(data)).digest();

    return new Uint8Array(hash).buffer;
  }

}
