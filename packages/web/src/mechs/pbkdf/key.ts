import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../key";

export class PbkdfCryptoKey extends CryptoKey {

  constructor(algorithm: types.KeyAlgorithm, extractable: boolean, usages: types.KeyUsage[], public raw: Uint8Array) {
    super(algorithm, extractable, "secret", usages);
  }

}
