import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getOidByNamedCurve } from "./helper";

export class EdPublicKey extends AsymmetricKey implements jsonSchema.IJsonConvertible {

  public readonly type: "public" = "public";
  public override algorithm!: types.EcKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, schema.PublicKeyInfo);
    return keyInfo.publicKey;
  }

  public toJSON() {
    const key = this.getKey();

    const json: types.JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, {
      x: pvtsutils.Convert.ToBase64Url(key)
    });
  }

  public fromJSON(json: types.JsonWebKey) {
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }
    if (!json.x) {
      throw new core.OperationError(`Cannot get property from JWK. Property 'x' is required`);
    }

    const keyInfo = new schema.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = getOidByNamedCurve(json.crv);
    keyInfo.publicKey = pvtsutils.Convert.FromBase64Url(json.x);

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    return this;
  }
}
