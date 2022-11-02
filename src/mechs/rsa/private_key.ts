import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { AsymmetricKey } from "../../keys";
import { getJwkAlgorithm } from "./helper";

export class RsaPrivateKey extends AsymmetricKey {
  public readonly type = "private" as const;
  public override algorithm!: RsaHashedKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, core.asn1.PrivateKeyInfo);
    return AsnParser.parse(keyInfo.privateKey, core.asn1.RsaPrivateKey);
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
    const key = JsonParser.fromJSON(json, { targetSchema: core.asn1.RsaPrivateKey });

    const keyInfo = new core.asn1.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;
    keyInfo.privateKey = AsnSerializer.serialize(key);

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));
  }

}
