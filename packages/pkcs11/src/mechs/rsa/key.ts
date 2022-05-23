import { CryptoKey } from "../../key";
import { Pkcs11RsaHashedKeyAlgorithm } from "../../types";

export class RsaCryptoKey extends CryptoKey<Pkcs11RsaHashedKeyAlgorithm> {

  protected override onAssign() {
    if (!this.algorithm.modulusLength) {
      this.algorithm.modulusLength = 0;
      try {
        this.algorithm.modulusLength = this.key.get("modulus").length << 3;
      } catch { /*nothing*/ }
    }

    if (!this.algorithm.publicExponent) {
      this.algorithm.publicExponent = new Uint8Array(0);
      try {
        let publicExponent = this.key.get("publicExponent") as Buffer;

        // Remove padding
        publicExponent = publicExponent.length > 3
          ? publicExponent.slice(publicExponent.length - 3)
          : publicExponent;

        this.algorithm.publicExponent = new Uint8Array(publicExponent);
      } catch { /*nothing*/ }
    }
  }

}
