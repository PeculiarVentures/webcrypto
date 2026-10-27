import { Buffer } from "node:buffer";
import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public data: Buffer = Buffer.alloc(0);

  public override algorithm: KeyAlgorithm = { name: "" };

  @JsonProp({
    name: "ext",
    type: JsonPropTypes.Boolean,
    optional: true,
  })
  public override extractable = false;

  public override type: KeyType = "secret";

  @JsonProp({
    name: "key_ops",
    type: JsonPropTypes.String,
    repeated: true,
    optional: true,
  })
  public override usages: KeyUsage[] = [];

  @JsonProp({ type: JsonPropTypes.String })
  protected kty = "oct";

  // An accessor, not a field: with ES2022 class fields an own `alg` property would hide
  // the getters of AesCryptoKey, DesCryptoKey and HmacCryptoKey, so JWK export got "".
  @JsonProp({
    type: JsonPropTypes.String,
    optional: true,
  })
  protected get alg(): string {
    return "";
  }

  protected set alg(_value: string) {
    // json-schema assigns `alg` on import; the value is derived from the algorithm
  }
}
