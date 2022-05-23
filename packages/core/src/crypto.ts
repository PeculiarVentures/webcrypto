import { Convert } from "pvtsutils";
import { SubtleCrypto } from "./subtle";
import * as types from "@peculiar/webcrypto-types";

export abstract class Crypto implements types.Crypto {

  public abstract readonly subtle: SubtleCrypto;

  // @internal
  public get [Symbol.toStringTag]() {
    return "Crypto";
  }

  public abstract getRandomValues<T extends ArrayBufferView | null>(array: T): T;

  public randomUUID(): string {
    const b = this.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const uuid = Convert.ToHex(b).toLowerCase();

    return `${uuid.substring(0, 8)}-${uuid.substring(8, 12)}-${uuid.substring(12, 16)}-${uuid.substring(16)}`;
  }

}
