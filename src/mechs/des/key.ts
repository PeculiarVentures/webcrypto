import { JsonProp } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { JsonBase64UrlConverter } from "../../converters";
import { SymmetricKey } from "../../keys";

export class DesCryptoKey extends SymmetricKey {

  public algorithm!: core.DesKeyAlgorithm;

  @JsonProp({name: "k", converter: JsonBase64UrlConverter})
  public data!: Buffer;

  public get alg() {
    switch (this.algorithm.name.toUpperCase()) {
      case "DES-CBC":
        return `DES-CBC`;
      case "DES-EDE3-CBC":
        return `3DES-CBC`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }

  public set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
