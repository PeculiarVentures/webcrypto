import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { JsonProp } from "@peculiar/json-schema";
import { AsnIntegerArrayBufferConverter, JsonBase64UrlArrayBufferConverter } from "../converters";

// RFC 3437
// https://tools.ietf.org/html/rfc3447#appendix-A.1.1
//
// RSAPublicKey ::= SEQUENCE {
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e
// }

export class RsaPublicKey {

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "n", converter: JsonBase64UrlArrayBufferConverter })
  public modulus = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "e", converter: JsonBase64UrlArrayBufferConverter })
  public publicExponent = new ArrayBuffer(0);

}
