import * as jsonSchema from "@peculiar/json-schema";
import * as types from "@peculiar/webcrypto-types";
import { JsonBase64UrlConverter } from "../../converters";
import { CryptoKey } from "../../keys";

export class HmacCryptoKey extends CryptoKey {

  @jsonSchema.JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public override data!: Buffer;

  public override algorithm!: types.HmacKeyAlgorithm;

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
