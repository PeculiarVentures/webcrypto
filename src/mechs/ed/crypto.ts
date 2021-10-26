import crypto from "crypto";
import { AsnParser } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKeyPair> {
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

  public static async sign(algorithm: Algorithm, key: EdPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    if (!key.pem) {
      key.pem = `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`;
    }
    const options = {
      key: key.pem,
    };
    const signature = crypto.sign(null, Buffer.from(data), options);

    return core.BufferSourceConverter.toArrayBuffer(signature);
  }

  public static async verify(algorithm: EcdsaParams, key: EdPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    if (!key.pem) {
      key.pem = `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`;
    }
    const options = {
      key: key.pem,
    };
    const ok = crypto.verify(null, Buffer.from(data), options, Buffer.from(signature));
    return ok;
  }

  public static async deriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
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

  public static async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "pkcs8":
      case "spki":
        return new Uint8Array(key.data).buffer;
      case "raw": {
        const publicKeyInfo = AsnParser.parse(key.data, core.asn1.PublicKeyInfo);
        return publicKeyInfo.publicKey;
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk = keyData as JsonWebKey;
        if (jwk.d) {
          const asnKey = JsonParser.fromJSON(keyData, { targetSchema: core.asn1.CurvePrivateKey });
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          if (!jwk.x) {
            throw new TypeError("keyData: Cannot get required 'x' filed");
          }
          return this.importPublicKey(Convert.FromBase64Url(jwk.x), algorithm, extractable, keyUsages);
        }
      }
      case "raw": {
        return this.importPublicKey(keyData as ArrayBuffer, algorithm, extractable, keyUsages);
      }
      case "spki": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PublicKeyInfo);
        return this.importPublicKey(keyInfo.publicKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PrivateKeyInfo);
        const asnKey = AsnParser.parse(keyInfo.privateKey, core.asn1.CurvePrivateKey);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  protected static importPrivateKey(asnKey: core.asn1.CurvePrivateKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const key = new EdPrivateKey();
    key.fromJSON({
      crv: algorithm.namedCurve,
      d: Convert.ToBase64Url(asnKey.d),
    });
    
    key.algorithm = Object.assign({}, algorithm) as EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;
    
    return key;
  }
  
  protected static async importPublicKey(asnKey: ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const key = new EdPublicKey();
    key.fromJSON({
      crv: algorithm.namedCurve,
      x: Convert.ToBase64Url(asnKey),
    });

    key.algorithm = Object.assign({}, algorithm) as EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

}
