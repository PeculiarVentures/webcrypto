import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getJwkAlgorithm } from "./helper";

export class RsaPublicKey extends AsymmetricKey {
  public readonly type: "public" = "public";
  public override algorithm!: RsaHashedKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, core.asn1.PublicKeyInfo);
    return AsnParser.parse(keyInfo.publicKey, core.asn1.RsaPublicKey);
  }

  public toJSON() {
    const key = this.getKey();

    const json: JsonWebKey = {
      kty: "RSA",
      alg: getJwkAlgorithm(this.algorithm),
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, JsonSerializer.toJSON(key));
  }

  public fromJSON(json: JsonWebKey) {
    const key = JsonParser.fromJSON(json, { targetSchema: core.asn1.RsaPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = AsnSerializer.serialize(key);

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));
  }
}
