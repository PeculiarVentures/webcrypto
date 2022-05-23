import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";

// RFC 8410
// https://datatracker.ietf.org/doc/html/rfc8410
//
// PublicKey ::= BIT STRING

@AsnType({ type: AsnTypeTypes.Choice })
export class EdPublicKey implements IJsonConvertible {

  @AsnProp({ type: AsnPropTypes.BitString })
  public value = new ArrayBuffer(0);

  constructor(value?: ArrayBuffer) {
    if (value) {
      this.value = value;
    }
  }

  public toJSON() {
    const json = {
      x: Convert.ToBase64Url(this.value),
    };

    return json;
  }

  public fromJSON(json: any): this {
    if (!("x" in json)) {
      throw new Error("x: Missing required property");
    }

    this.value = Convert.FromBase64Url(json.x);

    return this;
  }

}
