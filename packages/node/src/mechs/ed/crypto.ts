import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import * as pvtsutils from "pvtsutils";
import { CryptoKey } from "../../keys";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const privateKey = new EdPrivateKey();
    privateKey.algorithm = algorithm;
    privateKey.extractable = extractable;
    privateKey.usages = keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1);

    const publicKey = new EdPublicKey();
    publicKey.algorithm = algorithm;
    publicKey.extractable = true;
    publicKey.usages = keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1);

    const type = algorithm.namedCurve.toLowerCase() as "x448"; // "x448" | "ed448" | "x25519" | "ed25519"
    const keys = crypto.generateKeyPairSync(type, {
      publicKeyEncoding: {
        format: "der",
        type: "spki",
      },
      privateKeyEncoding: {
        format: "der",
        type: "pkcs8",
      },
    });

    privateKey.data = keys.privateKey;
    publicKey.data = keys.publicKey;

    const res = {
      privateKey,
      publicKey,
    };

    return res;
  }

  public static async sign(algorithm: types.Algorithm, key: EdPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    if (!key.pem) {
      key.pem = `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`;
    }
    const options = {
      key: key.pem,
    };
    const signature = crypto.sign(null, Buffer.from(data), options);

    return pvtsutils.BufferSourceConverter.toArrayBuffer(signature);
  }

  public static async verify(algorithm: types.EcdsaParams, key: EdPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    if (!key.pem) {
      key.pem = `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`;
    }
    const options = {
      key: key.pem,
    };
    const ok = crypto.verify(null, Buffer.from(data), options, Buffer.from(signature));
    return ok;
  }

  public static async deriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    const publicKey = crypto.createPublicKey({
      key: (algorithm.public as CryptoKey).data,
      format: "der",
      type: "spki",
    });
    const privateKey = crypto.createPrivateKey({
      key: baseKey.data,
      format: "der",
      type: "pkcs8",
    });
    const bits = crypto.diffieHellman({
      publicKey,
      privateKey,
    });

    return new Uint8Array(bits).buffer.slice(0, length >> 3);
  }

  public static async exportKey(format: types.KeyFormat, key: CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return jsonSchema.JsonSerializer.toJSON(key);
      case "pkcs8":
      case "spki":
        return new Uint8Array(key.data).buffer;
      case "raw": {
        const publicKeyInfo = asn1Schema.AsnParser.parse(key.data, core.PublicKeyInfo);
        return publicKeyInfo.publicKey;
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk = keyData as types.JsonWebKey;
        if (jwk.d) {
          const asnKey = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: core.CurvePrivateKey });
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          if (!jwk.x) {
            throw new TypeError("keyData: Cannot get required 'x' filed");
          }
          return this.importPublicKey(pvtsutils.Convert.FromBase64Url(jwk.x), algorithm, extractable, keyUsages);
        }
      }
      case "raw": {
        return this.importPublicKey(keyData as ArrayBuffer, algorithm, extractable, keyUsages);
      }
      case "spki": {
        const keyInfo = asn1Schema.AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.PublicKeyInfo);
        return this.importPublicKey(keyInfo.publicKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = asn1Schema.AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.PrivateKeyInfo);
        const asnKey = asn1Schema.AsnParser.parse(keyInfo.privateKey, core.CurvePrivateKey);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  protected static importPrivateKey(asnKey: core.CurvePrivateKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const key = new EdPrivateKey();
    key.fromJSON({
      crv: algorithm.namedCurve,
      d: pvtsutils.Convert.ToBase64Url(asnKey.d),
    });

    key.algorithm = Object.assign({}, algorithm) as types.EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  protected static async importPublicKey(asnKey: ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const key = new EdPublicKey();
    key.fromJSON({
      crv: algorithm.namedCurve,
      x: pvtsutils.Convert.ToBase64Url(asnKey),
    });

    key.algorithm = Object.assign({}, algorithm) as types.EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

}
