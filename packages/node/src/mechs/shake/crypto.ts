import * as crypto from "crypto";
import * as types from "@peculiar/webcrypto-types";

export class ShakeCrypto {

  public static digest(algorithm: Required<types.ShakeParams>, data: ArrayBuffer) {
    const hash = crypto.createHash(algorithm.name.toLowerCase(), { outputLength: algorithm.length })
      .update(Buffer.from(data)).digest();

    return new Uint8Array(hash).buffer;
  }

}
