import { AsnIntegerConverter, AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { JsonProp } from "@peculiar/json-schema";
import { AsnIntegerArrayBufferConverter, JsonBase64UrlArrayBufferConverter } from "../json/converters";

// RFC 3437
// https://tools.ietf.org/html/rfc3447#appendix-A.1.2
//
// RSAPrivateKey ::= SEQUENCE {
//   version           Version,
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e
//   privateExponent   INTEGER,  -- d
//   prime1            INTEGER,  -- p
//   prime2            INTEGER,  -- q
//   exponent1         INTEGER,  -- d mod (p-1)
//   exponent2         INTEGER,  -- d mod (q-1)
//   coefficient       INTEGER,  -- (inverse of q) mod p
//   otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }

export class RsaPrivateKey {

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerConverter })
  public version = 0;

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "n", converter: JsonBase64UrlArrayBufferConverter })
  public modulus = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "e", converter: JsonBase64UrlArrayBufferConverter })
  public publicExponent = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "d", converter: JsonBase64UrlArrayBufferConverter })
  public privateExponent = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "p", converter: JsonBase64UrlArrayBufferConverter })
  public prime1 = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "q", converter: JsonBase64UrlArrayBufferConverter })
  public prime2 = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "dp", converter: JsonBase64UrlArrayBufferConverter })
  public exponent1 = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "dq", converter: JsonBase64UrlArrayBufferConverter })
  public exponent2 = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
  @JsonProp({ name: "qi", converter: JsonBase64UrlArrayBufferConverter })
  public coefficient = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Any, optional: true })
  public otherPrimeInfos?: ArrayBuffer;

}
