import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getOidByNamedCurve } from "./helper";

export class EcPublicKey extends AsymmetricKey implements jsonSchema.IJsonConvertible {

  public readonly type: "public" = "public";
  public override algorithm!: types.EcKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, core.asn1.PublicKeyInfo);
    return new core.asn1.EcPublicKey(keyInfo.publicKey);
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

    const key = jsonSchema.JsonParser.fromJSON(json, { targetSchema: core.asn1.EcPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.publicKeyAlgorithm.parameters = asn1Schema.AsnSerializer.serialize(
      new core.asn1.ObjectIdentifier(getOidByNamedCurve(json.crv)),
    );
    keyInfo.publicKey = asn1Schema.AsnSerializer.toASN(key).valueHex;

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    return this;
  }
}
