import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { CryptoKey } from "../../key";

export class DesCryptoKey extends CryptoKey {
  declare public algorithm: types.DesKeyAlgorithm;

  constructor(algorithm: types.DesKeyAlgorithm, extractable: boolean, usages: types.KeyUsage[], public raw: Uint8Array) {
    super(algorithm, extractable, "secret", usages);
  }

  public toJSON() {
    const jwk: types.JsonWebKey = {
      kty: "oct",
      alg: this.getJwkAlgorithm(),
      k: pvtsutils.Convert.ToBase64Url(this.raw),
      ext: this.extractable,
      key_ops: this.usages,
    };
    return jwk;
  }

  private getJwkAlgorithm() {
    switch (this.algorithm.name.toUpperCase()) {
      case "DES-CBC":
        return `DES-CBC`;
      case "DES-EDE3-CBC":
        return `3DES-CBC`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }

}
