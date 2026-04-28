import type { Buffer } from "node:buffer";
import { CryptoKey } from "../../keys";

export class HkdfCryptoKey extends CryptoKey {
  public declare data: Buffer;

  public declare algorithm: KeyAlgorithm;
}
