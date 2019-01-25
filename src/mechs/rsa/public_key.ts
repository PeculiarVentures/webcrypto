import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as asn from "../../asn";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getJwkAlgorithm } from "./helper";

export class RsaPublicKey extends AsymmetricKey {
  public readonly type: "public" = "public";
  public algorithm!: RsaHashedKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, asn.PublicKeyInfo);
    return AsnParser.parse(keyInfo.publicKey, asn.RsaPublicKey);
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
    const key = JsonParser.fromJSON(json, { targetSchema: asn.RsaPublicKey });

    const keyInfo = new asn.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = AsnSerializer.serialize(key);

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));
  }
}
