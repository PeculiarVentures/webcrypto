import { IAsnConverter } from "@peculiar/asn1-schema";
import * as asn1 from "asn1js";

export const AsnIntegerArrayBufferConverter: IAsnConverter<ArrayBuffer> = {
  fromASN: (value: asn1.Integer) => {
    return value.convertFromDER().valueBlock.valueHexView.slice().buffer;
  },
  toASN: (value: ArrayBuffer) => {
    return new asn1.Integer({ valueHex: value }).convertToDER();
  },
};
