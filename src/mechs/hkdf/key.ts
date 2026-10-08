import type { Buffer } from "node:buffer";
import { CryptoKey } from "../../keys";

export class HkdfCryptoKey extends CryptoKey {
  declare public data: Buffer;

  declare public algorithm: KeyAlgorithm;
}
