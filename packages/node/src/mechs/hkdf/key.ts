import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../keys";

export class HkdfCryptoKey extends CryptoKey {

  public override data!: Buffer;

  public override algorithm!: types.KeyAlgorithm;
}
