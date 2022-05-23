import { JsonProp } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { JsonBase64UrlConverter } from "../../converters";
import { SymmetricKey } from "../../keys";

export class AesCryptoKey extends SymmetricKey {

  public override algorithm!: types.AesKeyAlgorithm;

  @JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public override data!: Buffer;

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  public override get alg() {
    switch (this.algorithm.name.toUpperCase()) {
      case "AES-CBC":
        return `A${this.algorithm.length}CBC`;
      case "AES-CTR":
        return `A${this.algorithm.length}CTR`;
      case "AES-GCM":
        return `A${this.algorithm.length}GCM`;
      case "AES-KW":
        return `A${this.algorithm.length}KW`;
      case "AES-CMAC":
        return `A${this.algorithm.length}CMAC`;
      case "AES-ECB":
        return `A${this.algorithm.length}ECB`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }

  public override set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
