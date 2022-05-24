import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { JsonBase64UrlConverter } from "../../converters";
import { SymmetricKey } from "../../keys";

export class DesCryptoKey extends SymmetricKey {

  public override algorithm!: types.DesKeyAlgorithm;

  @jsonSchema.JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public override data!: Buffer;

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
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

  public override set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
