import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import { AsymmetricKey } from "../../keys";
import { getOidByNamedCurve } from "./helper";

export class EcPrivateKey extends AsymmetricKey implements jsonSchema.IJsonConvertible {
  public readonly type: "private" = "private";
  public override algorithm!: types.EcKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, schema.PrivateKeyInfo);
    return asn1Schema.AsnParser.parse(keyInfo.privateKey, schema.EcPrivateKey);
  }

  public toJSON() {
    const key = this.getKey();

    const json: types.JsonWebKey = {
      kty: "EC",
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
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.privateKeyAlgorithm.parameters = asn1Schema.AsnSerializer.serialize(
      new schema.ObjectIdentifier(getOidByNamedCurve(json.crv)),
    );
    const key = jsonSchema.JsonParser.fromJSON(json, { targetSchema: schema.EcPrivateKey });
    keyInfo.privateKey = asn1Schema.AsnSerializer.serialize(key);

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    return this;
  }

}
