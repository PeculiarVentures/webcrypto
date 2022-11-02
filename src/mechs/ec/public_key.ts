import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { IJsonConvertible, JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getOidByNamedCurve } from "./helper";

export class EcPublicKey extends AsymmetricKey implements IJsonConvertible {

  public readonly type = "public" as const;
  public override algorithm!: EcKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, core.asn1.PublicKeyInfo);
    return new core.asn1.EcPublicKey(keyInfo.publicKey);
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

    const key = JsonParser.fromJSON(json, { targetSchema: core.asn1.EcPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(
      new core.asn1.ObjectIdentifier(getOidByNamedCurve(json.crv)),
    );
    keyInfo.publicKey = (AsnSerializer.toASN(key) as any).valueHex;

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    return this;
  }
}
