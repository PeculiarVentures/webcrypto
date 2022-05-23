import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { AsymmetricKey } from "../../keys";
import { getJwkAlgorithm } from "./helper";

export class RsaPrivateKey extends AsymmetricKey {
  public readonly type: "private" = "private";
  public override algorithm!: types.RsaHashedKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, core.PrivateKeyInfo);
    return asn1Schema.AsnParser.parse(keyInfo.privateKey, core.RsaPrivateKey);
  }

  public toJSON() {
    const key = this.getKey();

    const json: types.JsonWebKey = {
      kty: "RSA",
      alg: getJwkAlgorithm(this.algorithm),
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, jsonSchema.JsonSerializer.toJSON(key));
  }

  public fromJSON(json: types.JsonWebKey) {
    const key = jsonSchema.JsonParser.fromJSON(json, { targetSchema: core.RsaPrivateKey });

    const keyInfo = new core.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;
    keyInfo.privateKey = asn1Schema.AsnSerializer.serialize(key);

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));
  }

}
