import { AsnIntegerConverter, AsnProp, AsnPropTypes, AsnSerializer } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";
import { EcPublicKey } from "./ec_public_key";

// RFC 5915
// https://tools.ietf.org/html/rfc5915#section-3
//
// ECPrivateKey ::= SEQUENCE {
//   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey     OCTET STRING,
//   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//   publicKey  [1] BIT STRING OPTIONAL
// }

export class EcPrivateKey implements IJsonConvertible {

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerConverter })
  public version = 1;

  @AsnProp({ type: AsnPropTypes.OctetString })
  public privateKey = new ArrayBuffer(0);

  @AsnProp({ context: 0, type: AsnPropTypes.Any, optional: true })
  public parameters?: ArrayBuffer;

  @AsnProp({ context: 1, type: AsnPropTypes.BitString, optional: true })
  public publicKey?: ArrayBuffer;

  public fromJSON(json: any): this {
    if (!("d" in json)) {
      throw new Error("d: Missing required property");
    }
    this.privateKey = Convert.FromBase64Url(json.d);

    if ("x" in json) {
      const publicKey = new EcPublicKey();
      publicKey.fromJSON(json);

      this.publicKey = AsnSerializer.toASN(publicKey).valueBlock.valueHex;
    }

    return this;
  }
  public toJSON() {
    const jwk: JsonWebKey = {};
    jwk.d = Convert.ToBase64Url(this.privateKey);
    if (this.publicKey) {
      Object.assign(jwk, new EcPublicKey(this.publicKey).toJSON());
    }
    return jwk;
  }

}
