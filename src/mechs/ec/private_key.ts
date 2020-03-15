import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { IJsonConvertible, JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import * as asn from "../../asn";
import { ObjectIdentifier } from "../../asn";
import { AsymmetricKey } from "../../keys";
import { getOidByNamedCurve } from "./helper";

export class EcPrivateKey extends AsymmetricKey implements IJsonConvertible {
  public readonly type: "private" = "private";
  public algorithm!: EcKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, asn.PrivateKeyInfo);
    return AsnParser.parse(keyInfo.privateKey, asn.EcPrivateKey);
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
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }

    const keyInfo = new asn.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(
      new ObjectIdentifier(getOidByNamedCurve(json.crv)),
    );
    const key = JsonParser.fromJSON(json, { targetSchema: asn.EcPrivateKey });
    keyInfo.privateKey = AsnSerializer.serialize(key);

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    return this;
  }

}
