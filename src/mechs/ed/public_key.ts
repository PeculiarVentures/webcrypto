import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { AsymmetricKey } from "../../keys/asymmetric";
import { getOidByNamedCurve } from "./helper";

export class EdPublicKey extends AsymmetricKey implements IJsonConvertible {

  public readonly type = "public" as const;
  public override algorithm!: EcKeyAlgorithm;

  public getKey() {
    const keyInfo = AsnParser.parse(this.data, core.asn1.PublicKeyInfo);
    return keyInfo.publicKey;
  }

  public toJSON() {
    const key = this.getKey();

    const json: JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, {
      x: Convert.ToBase64Url(key)
    });
  }

  public fromJSON(json: JsonWebKey) {
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }
    if (!json.x) {
      throw new core.OperationError(`Cannot get property from JWK. Property 'x' is required`);
    }

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = getOidByNamedCurve(json.crv);
    keyInfo.publicKey = Convert.FromBase64Url(json.x);

    this.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    return this;
  }
}
