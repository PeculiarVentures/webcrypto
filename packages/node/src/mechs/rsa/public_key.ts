import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getJwkAlgorithm } from "./helper";

export class RsaPublicKey extends AsymmetricKey {
  public readonly type: "public" = "public";
  public override algorithm!: types.RsaHashedKeyAlgorithm;

  public getKey() {
    const keyInfo = asn1Schema.AsnParser.parse(this.data, core.asn1.PublicKeyInfo);
    return asn1Schema.AsnParser.parse(keyInfo.publicKey, core.asn1.RsaPublicKey);
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
    const key = jsonSchema.JsonParser.fromJSON(json, { targetSchema: core.asn1.RsaPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = asn1Schema.AsnSerializer.serialize(key);

    this.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));
  }
}
