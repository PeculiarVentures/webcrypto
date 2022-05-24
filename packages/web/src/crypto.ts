import * as core from "@peculiar/webcrypto-core";
import { nativeCrypto } from "./native";
import { SubtleCrypto } from "./subtle";

export class Crypto extends core.Crypto {

  public get nativeCrypto() {
    return nativeCrypto;
  }

  public subtle = new SubtleCrypto();

  getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    return nativeCrypto.getRandomValues(array as any);
  }

}
