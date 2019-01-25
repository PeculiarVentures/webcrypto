import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public data: Buffer = Buffer.alloc(0);

  public algorithm: KeyAlgorithm = { name: "" };

  @JsonProp({ name: "ext", type: JsonPropTypes.Boolean, optional: true })
  public extractable: boolean = false;

  public type: KeyType = "secret";

  @JsonProp({ name: "key_ops", type: JsonPropTypes.String, repeated: true, optional: true })
  public usages: KeyUsage[] = [];

  @JsonProp({ type: JsonPropTypes.String })
  protected kty: string = "";

  @JsonProp({ type: JsonPropTypes.String })
  protected alg: string = "";
}
