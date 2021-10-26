import crypto from "crypto";
import * as core from "webcrypto-core";
import { SubtleCrypto } from "./subtle";

export class Crypto extends core.Crypto {

  public subtle = new SubtleCrypto();

  public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    if (!ArrayBuffer.isView(array)) {
      throw new TypeError("Failed to execute 'getRandomValues' on 'Crypto': parameter 1 is not of type 'ArrayBufferView'");
    }
    const buffer = Buffer.from(array.buffer);
    crypto.randomFillSync(buffer);
    return array;
  }

}
