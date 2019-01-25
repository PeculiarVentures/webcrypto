import crypto from "crypto";
import * as core from "webcrypto-core";
import { SubtleCrypto } from "./subtle";

export class Crypto implements core.Crypto {

  public subtle = new SubtleCrypto();

  public getRandomValues<T extends ArrayBufferView>(array: T): T {
    const buffer = Buffer.from(array.buffer);
    crypto.randomFillSync(buffer);
    return array;
  }

}
