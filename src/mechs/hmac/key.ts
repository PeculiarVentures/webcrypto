import { JsonProp } from "@peculiar/json-schema";
import { JsonBase64UrlConverter } from "../../converters";
import { CryptoKey } from "../../keys";

export class HmacCryptoKey extends CryptoKey {

  @JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public data!: Buffer;

  public algorithm!: HmacKeyAlgorithm;

  protected get alg() {
    const hash = this.algorithm.hash.name.toUpperCase();
    return `HS${hash.replace("SHA-", "")}`;
  }

  protected set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
