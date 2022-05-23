import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";

@AsnType({ type: AsnTypeTypes.Choice })
export class EdPrivateKey implements IJsonConvertible {

  @AsnProp({ type: AsnPropTypes.OctetString })
  public value = new ArrayBuffer(0);

  public fromJSON(json: any): this {
    if (!json.d) {
      throw new Error("d: Missing required property");
    }
    this.value = Convert.FromBase64Url(json.d);

    return this;
  }
  public toJSON() {
    const jwk: types.JsonWebKey = {
      d: Convert.ToBase64Url(this.value),
    };

    return jwk;
  }
}
