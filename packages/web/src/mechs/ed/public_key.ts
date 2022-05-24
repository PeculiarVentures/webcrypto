import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as elliptic from "elliptic";
import * as pvtsutils from "pvtsutils";
import { CryptoKey } from "../../key";

export class EdPublicKey extends CryptoKey implements jsonSchema.IJsonConvertible {

  declare public algorithm: types.EcKeyAlgorithm;

  public constructor(algorithm: types.EcKeyAlgorithm, extractable: boolean, usages: types.KeyUsage[], public data: EllipticJS.EllipticKeyPair) {
    super(algorithm, extractable, "public", usages);
  }

  public toJSON() {
    const json: types.JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, {
      x: pvtsutils.Convert.ToBase64Url(pvtsutils.Convert.FromHex(this.data.getPublic("hex"))),
    });
  }

  public fromJSON(json: types.JsonWebKey) {
    if (!json.crv) {
      // TODO use core.RequiredPropertyError
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }
    if (!json.x) {
      throw new core.OperationError(`Cannot get property from JWK. Property 'x' is required`);
    }

    const hexPublicKey = pvtsutils.Convert.ToHex(pvtsutils.Convert.FromBase64Url(json.x));
    if (/^ed/i.test(json.crv)) {
      const eddsa = new elliptic.eddsa(json.crv.toLowerCase());
      this.data = eddsa.keyFromPublic(hexPublicKey, "hex");
    } else {
      const ecdhEs = elliptic.ec(json.crv.replace(/^x/i, "curve"));
      this.data = ecdhEs.keyFromPublic(hexPublicKey, "hex");
    }

    return this;
  }
}
