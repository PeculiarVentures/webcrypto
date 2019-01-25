import { AsnIntegerArrayBufferConverter, AsnProp, AsnPropTypes, IAsnConverter } from "@peculiar/asn1-schema";
// tslint:disable-next-line: no-var-requires
const asn1 = require("asn1js");

// RFC 3279
// https://tools.ietf.org/html/rfc3279#section-2.2.3
//
// ECDSA-Sig-Value ::= SEQUENCE {
//   r  INTEGER,
//   s  INTEGER
// }

export const AsnIntegerWithoutPaddingConverter: IAsnConverter<ArrayBuffer> = {
  fromASN: (value: any) => {
    const bytes = new Uint8Array(value.valueBlock.valueHex);
    return (bytes[0] === 0)
      ? bytes.buffer.slice(1)
      : bytes.buffer;
  },
  toASN: (value: ArrayBuffer) => {
    const bytes = new Uint8Array(value);
    if (bytes[0] > 128) {
      const newValue = new Uint8Array(bytes.length + 1);
      newValue.set(bytes, 1);
      return new asn1.Integer({ valueHex: newValue });
    }
    return new asn1.Integer({ valueHex: value });
  },
};

export class EcDsaSignature {

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public r = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public s = new ArrayBuffer(0);

}
