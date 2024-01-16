import type { Buffer } from "buffer";
import { JsonProp } from "@peculiar/json-schema";
import { JsonBase64UrlConverter } from "../../converters";
import { CryptoKey } from "../../keys";

export class HmacCryptoKey extends CryptoKey {

  @JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public override data!: Buffer;

  public override algorithm!: HmacKeyAlgorithm;

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  protected get alg() {
    const hash = this.algorithm.hash.name.toUpperCase();
    return `HS${hash.replace("SHA-", "")}`;
  }

  protected override set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

}
