import { CryptoKey } from "../../key";
import { Pkcs11AesKeyAlgorithm } from "../../types";

export class AesCryptoKey extends CryptoKey<Pkcs11AesKeyAlgorithm> {

  protected override onAssign() {
    this.algorithm.length = this.key.get("valueLen") << 3;
  }

}
