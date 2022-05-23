import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import { AsymmetricKey } from "../../keys";
import { getOidByNamedCurve } from "./helper";

export class EdPrivateKey extends AsymmetricKey implements jsonSchema.IJsonConvertible {
  public readonly type: "private" = "private";
  public override algorithm!: types.EcKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, schema.PrivateKeyInfo);
    return asn1Schema.AsnParser.parse(keyInfo.privateKey, schema.CurvePrivateKey);
  }

  public toJSON() {
    const key = this.getKey();

    const json: types.JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, jsonSchema.JsonSerializer.toJSON(key));
  }

  public fromJSON(json: types.JsonWebKey) {
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }

    const keyInfo = new schema.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = getOidByNamedCurve(json.crv);
    const key = jsonSchema.JsonParser.fromJSON(json, { targetSchema: schema.CurvePrivateKey });
    keyInfo.privateKey = asn1Schema.AsnSerializer.serialize(key);

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    return this;
  }

}
