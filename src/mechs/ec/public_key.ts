import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { IJsonConvertible, JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as asn from "../../asn";
import { ObjectIdentifier } from "../../asn";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getOidByNamedCurve } from "./helper";

export class EcPublicKey extends AsymmetricKey implements IJsonConvertible {

  public readonly type: "public" = "public";
  public algorithm!: EcKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, asn.PublicKeyInfo);
    return new asn.EcPublicKey(keyInfo.publicKey);
  }

  public toJSON() {
    const key = this.getKey();

    const json: JsonWebKey = {
      kty: "EC",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, JsonSerializer.toJSON(key));
  }

  public fromJSON(json: JsonWebKey) {
    const key = JsonParser.fromJSON(json, asn.EcPublicKey);

    const keyInfo = new asn.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(
      new ObjectIdentifier(getOidByNamedCurve(json.crv!)),
    );
    keyInfo.publicKey = AsnSerializer.toASN(key).valueHex;

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    return this;
  }
}
