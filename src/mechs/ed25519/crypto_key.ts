import { CryptoKey } from "../../keys";

export class Ed25519CryptoKey extends CryptoKey {

  constructor(algorithm: Algorithm, extractable: boolean, usages: KeyUsage[], data: string) {
    super();
    this.algorithm = algorithm;
    this.extractable = extractable;
    this.usages = usages;
    this.data = Buffer.from(data);
  }

  public toJWK(): JsonWebKey {
    return {
      kty: "OKP",
      crv: this.algorithm.name,
      key_ops: this.usages,
      ext: this.extractable,
    };
  }
}
