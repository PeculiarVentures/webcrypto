import * as jsonSchema from "@peculiar/json-schema";
import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { CryptoKey } from "../../key";

export const JsonBase64UrlConverter: jsonSchema.IJsonConverter<Buffer, string> = {
  fromJSON: (value: string) => Buffer.from(pvtsutils.Convert.FromBase64Url(value)),
  toJSON: (value: Buffer) => pvtsutils.Convert.ToBase64Url(value),
};

export class HmacCryptoKey extends CryptoKey {

  @jsonSchema.JsonProp({ name: "ext", type: jsonSchema.JsonPropTypes.Boolean, optional: true })
  public override extractable!: boolean;

  declare public readonly type: "secret";

  @jsonSchema.JsonProp({ name: "key_ops", type: jsonSchema.JsonPropTypes.String, repeated: true, optional: true })
  public override usages!: types.KeyUsage[];

  @jsonSchema.JsonProp({ name: "k", converter: JsonBase64UrlConverter })
  public data: Uint8Array;

  declare public algorithm: types.HmacKeyAlgorithm;

  @jsonSchema.JsonProp({ type: jsonSchema.JsonPropTypes.String })
  protected readonly kty: string = "oct";

  @jsonSchema.JsonProp({ type: jsonSchema.JsonPropTypes.String })
  protected get alg() {
    const hash = this.algorithm.hash.name.toUpperCase();
    return `HS${hash.replace("SHA-", "")}`;
  }

  protected set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

  constructor();
  constructor(
    algorithm: types.KeyAlgorithm,
    extractable: boolean,
    usages: types.KeyUsage[],
    data: Uint8Array,
  );
  constructor(
    algorithm = { name: "HMAC" },
    extractable = false,
    usages: types.KeyUsage[] = [],
    data = new Uint8Array(0),
  ) {
    super(algorithm, extractable, "secret", usages);
    this.data = data;
  }

}
