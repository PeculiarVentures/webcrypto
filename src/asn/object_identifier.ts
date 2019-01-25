import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";

@AsnType({ type: AsnTypeTypes.Choice })
export class ObjectIdentifier {

  @AsnProp({type: AsnPropTypes.ObjectIdentifier})
  public value!: string;

  constructor(value?: string) {
    if (value) {
      this.value = value;
    }
  }
}
