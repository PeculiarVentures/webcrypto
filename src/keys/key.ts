import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public data: Buffer = Buffer.alloc(0);

  public override algorithm: KeyAlgorithm = { name: "" };

  @JsonProp({ name: "ext", type: JsonPropTypes.Boolean, optional: true })
  public override extractable = false;

  public override type: KeyType = "secret";

  @JsonProp({ name: "key_ops", type: JsonPropTypes.String, repeated: true, optional: true })
  public override usages: KeyUsage[] = [];

  @JsonProp({ type: JsonPropTypes.String })
  protected kty = "oct";

  @JsonProp({ type: JsonPropTypes.String, optional: true })
  protected alg = "";
}
