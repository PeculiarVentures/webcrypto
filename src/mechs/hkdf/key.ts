import type { Buffer } from "buffer";
import { CryptoKey } from "../../keys";

export class HkdfCryptoKey extends CryptoKey {

  public override data!: Buffer;

  public override algorithm!: KeyAlgorithm;
}
