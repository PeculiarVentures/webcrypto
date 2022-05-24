import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { CryptoKey } from "../../key";

export class AesCryptoKey extends CryptoKey {
  declare public algorithm: types.AesKeyAlgorithm;

  constructor(algorithm: types.AesKeyAlgorithm, extractable: boolean, usages: types.KeyUsage[], public raw: Uint8Array) {
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
      case "AES-CBC":
        return `A${this.algorithm.length}CBC`;
      case "AES-CTR":
        return `A${this.algorithm.length}CTR`;
      case "AES-GCM":
        return `A${this.algorithm.length}GCM`;
      case "AES-ECB":
        return `A${this.algorithm.length}ECB`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }
}
