import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

export class CryptoKey extends core.BaseCryptoKey {
  public data: Buffer = Buffer.alloc(0);

  public override algorithm: types.KeyAlgorithm = { name: "" };

  @JsonProp({ name: "ext", type: JsonPropTypes.Boolean, optional: true })
  public override extractable = false;

  public override type: types.KeyType = "secret";

  @JsonProp({ name: "key_ops", type: JsonPropTypes.String, repeated: true, optional: true })
  public override usages: types.KeyUsage[] = [];

  @JsonProp({ type: JsonPropTypes.String })
  protected kty = "oct";

  @JsonProp({ type: JsonPropTypes.String, optional: true })
  protected alg = "";
}
