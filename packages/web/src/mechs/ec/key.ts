/// <reference path="../../typings/elliptic.d.ts" />

import { EcKeyAlgorithm, KeyType, KeyUsage } from "@peculiar/webcrypto-types";
import { CryptoKey } from "../../key";

export class EcCryptoKey extends CryptoKey {

  declare public algorithm: EcKeyAlgorithm;

  constructor(algorithm: EcKeyAlgorithm, extractable: boolean, type: KeyType, usages: KeyUsage[], public data: EllipticJS.EllipticKeyPair) {
    super(algorithm, extractable, type, usages);
  }
}
