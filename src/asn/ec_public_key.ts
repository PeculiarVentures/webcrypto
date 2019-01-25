import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";

// RFC 5480
// https://tools.ietf.org/html/rfc5480#section-2.2
//
// ECPoint ::= OCTET STRING

@AsnType({ type: AsnTypeTypes.Choice })
export class EcPublicKey implements IJsonConvertible {

  @AsnProp({ type: AsnPropTypes.OctetString })
  public value = new ArrayBuffer(0);

  constructor(value?: ArrayBuffer) {
    if (value) {
      this.value = value;
    }
  }

  public toJSON() {
    let bytes = new Uint8Array(this.value);

    if (bytes[0] !== 0x04) {
      throw new core.CryptoError("Wrong ECPoint. Current version supports only Uncompressed (0x04) point");
    }

    bytes = new Uint8Array(this.value.slice(1));
    const size = bytes.length / 2;

    const offset = 0;
    const json = {
      x: Convert.ToBase64Url(bytes.buffer.slice(offset, offset + size)),
      y: Convert.ToBase64Url(bytes.buffer.slice(offset + size, offset + size + size)),
    };

    return json;
  }

  public fromJSON(json: any): this {
    if (!("x" in json)) {
      throw new Error("x: Missing required property");
    }
    if (!("y" in json)) {
      throw new Error("y: Missing required property");
    }

    const x = Convert.FromBase64Url(json.x);
    const y = Convert.FromBase64Url(json.y);

    const value = Buffer.concat([
      new Uint8Array([0x04]), // uncompressed bit
      new Uint8Array(x),
      new Uint8Array(y),
    ]);

    this.value = new Uint8Array(value).buffer;

    return this;
  }

}
