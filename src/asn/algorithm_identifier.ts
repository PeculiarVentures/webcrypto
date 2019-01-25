import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

// RFC 5280
// https://tools.ietf.org/html/rfc5280#section-4.1.1.2
//
// AlgorithmIdentifier  ::=  SEQUENCE  {
//   algorithm               OBJECT IDENTIFIER,
//   parameters              ANY DEFINED BY algorithm OPTIONAL  }
//                              -- contains a value of the type
//                              -- registered for use with the
//                              -- algorithm object identifier value

export type ParametersType = ArrayBuffer | null;

export class AlgorithmIdentifier {

  @AsnProp({
    type: AsnPropTypes.ObjectIdentifier,
  })
  public algorithm!: string;

  @AsnProp({
    type: AsnPropTypes.Any,
    optional: true,
  })
  public parameters?: ParametersType;

  constructor(params?: Partial<AlgorithmIdentifier>) {
    Object.assign(this, params);
  }
}
