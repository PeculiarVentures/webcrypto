import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

export class CryptoKey extends core.CryptoKey {
  public override algorithm: types.KeyAlgorithm;
  constructor(
    algorithm: types.KeyAlgorithm,
    public override extractable: boolean,
    public override type: types.KeyType,
    public override usages: types.KeyUsage[],
  ) {
    super();
    this.algorithm = { ...algorithm };
  }
}
