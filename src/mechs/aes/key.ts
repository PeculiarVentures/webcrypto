import { JsonProp } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { JsonBase64UrlConverter } from "../../converters";
import { SymmetricKey } from "../../keys";

export class AesCryptoKey extends SymmetricKey {

  public algorithm!: AesKeyAlgorithm;

  @JsonProp({name: "k", converter: JsonBase64UrlConverter})
  public data!: Buffer;

  public get alg() {
    switch (this.algorithm.name.toUpperCase()) {
      case "AES-CBC":
        return `A${this.algorithm.length}CBC`;
      case "AES-CTR":
        return `A${this.algorithm.length}CTR`;
      case "AES-GCM":
        return `A${this.algorithm.length}GCM`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }

  public set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
