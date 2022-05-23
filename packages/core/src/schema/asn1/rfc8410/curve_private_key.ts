import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import { JsonBase64UrlArrayBufferConverter } from "../../json/converters";

/**
 * ASN.1
 * ```
 * CurvePrivateKey ::= OCTET STRING
 * ```
 *
 * JSON
 * ```json
 * {
 *   "d": "base64url"
 * }
 * ```
 */
@AsnType({ type: AsnTypeTypes.Choice })
export class CurvePrivateKey {

  @AsnProp({ type: AsnPropTypes.OctetString })
  @JsonProp({ type: JsonPropTypes.String, converter: JsonBase64UrlArrayBufferConverter })
  public d!: ArrayBuffer;
}
