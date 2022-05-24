import * as types from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../key";
import { AsmCryptoRsaKey } from "./crypto";

export class RsaCryptoKey extends CryptoKey {

  declare public algorithm: types.RsaHashedKeyAlgorithm;

  constructor(algorithm: types.RsaHashedKeyAlgorithm, extractable: boolean, type: types.KeyType, usages: types.KeyUsage[], public data: AsmCryptoRsaKey) {
    super(algorithm, extractable, type, usages);
  }
}
