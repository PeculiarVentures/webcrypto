import { CryptoKey } from "../../keys";

export class HkdfCryptoKey extends CryptoKey {

  public data!: Buffer;

  public algorithm!: KeyAlgorithm;
}
