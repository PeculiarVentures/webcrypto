import { IAsnConverter } from "@peculiar/asn1-schema";
import * as asn1 from "asn1js";

export const AsnIntegerWithoutPaddingConverter: IAsnConverter<ArrayBuffer> = {
  fromASN: (value: any) => {
    const bytes = new Uint8Array(value.valueBlock.valueHex);
    return (bytes[0] === 0)
      ? bytes.buffer.slice(1)
      : bytes.buffer;
  },
  toASN: (value: ArrayBuffer): any => {
    const bytes = new Uint8Array(value);
    if (bytes[0] > 127) {
      const newValue = new Uint8Array(bytes.length + 1);
      newValue.set(bytes, 1);
      return new asn1.Integer({ valueHex: newValue.buffer } as any);
    }
    return new asn1.Integer({ valueHex: value } as any);
  },
};
