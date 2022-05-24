import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "./key";

export class WrappedNativeCryptoKey extends CryptoKey {

  #nativeKey: types.CryptoKey;

  constructor(
    algorithm: types.KeyAlgorithm,
    extractable: boolean,
    type: types.KeyType,
    usages: types.KeyUsage[],
    nativeKey: types.CryptoKey) {
    super(algorithm, extractable, type, usages);
    this.#nativeKey = nativeKey;
  }

  // @internal
  public getNative() {
    return this.#nativeKey;
  }

}
