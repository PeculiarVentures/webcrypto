import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { BufferSourceConverter } from "pvtsutils";
import { CryptoKey } from "../../keys";
import { ShaCrypto } from "../sha";
import { getOidByNamedCurve } from "./helper";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const privateKey = new EcPrivateKey();
    privateKey.algorithm = algorithm;
    privateKey.extractable = extractable;
    privateKey.usages = keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1);

    const publicKey = new EcPublicKey();
    publicKey.algorithm = algorithm;
    publicKey.extractable = true;
    publicKey.usages = keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1);

    const keys = crypto.generateKeyPairSync("ec", {
      namedCurve: this.getOpenSSLNamedCurve(algorithm.namedCurve),
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

  public static async sign(algorithm: types.EcdsaParams, key: EcPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    const cryptoAlg = ShaCrypto.getAlgorithmName(algorithm.hash as types.Algorithm);
    const signer = crypto.createSign(cryptoAlg);
    signer.update(Buffer.from(data));

    if (!key.pem) {
      key.pem = `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`;
    }
    const options = {
      key: key.pem,
    };

    const signature = signer.sign(options);
    const ecSignature = AsnParser.parse(signature, schema.EcDsaSignature);

    const signatureRaw = core.EcUtils.encodeSignature(ecSignature, core.EcCurves.get(key.algorithm.namedCurve).size);

    return signatureRaw.buffer;
  }

  public static async verify(algorithm: types.EcdsaParams, key: EcPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    const cryptoAlg = ShaCrypto.getAlgorithmName(algorithm.hash as types.Algorithm);
    const signer = crypto.createVerify(cryptoAlg);
    signer.update(Buffer.from(data));

    if (!key.pem) {
      key.pem = `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`;
    }
    const options = {
      key: key.pem,
    };

    const ecSignature = new schema.EcDsaSignature();
    const namedCurve = core.EcCurves.get(key.algorithm.namedCurve);
    const signaturePoint = core.EcUtils.decodeSignature(signature, namedCurve.size);
    ecSignature.r = BufferSourceConverter.toArrayBuffer(signaturePoint.r);
    ecSignature.s = BufferSourceConverter.toArrayBuffer(signaturePoint.s);

    const ecSignatureRaw = Buffer.from(AsnSerializer.serialize(ecSignature));
    const ok = signer.verify(options, ecSignatureRaw);
    return ok;
  }

  public static async deriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    const cryptoAlg = this.getOpenSSLNamedCurve((baseKey.algorithm as types.EcKeyAlgorithm).namedCurve);

    const ecdh = crypto.createECDH(cryptoAlg);
    const asnPrivateKey = AsnParser.parse(baseKey.data, schema.PrivateKeyInfo);
    const asnEcPrivateKey = AsnParser.parse(asnPrivateKey.privateKey, schema.EcPrivateKey);
    ecdh.setPrivateKey(Buffer.from(asnEcPrivateKey.privateKey));

    const asnPublicKey = AsnParser.parse((algorithm.public as CryptoKey).data, schema.PublicKeyInfo);
    const bits = ecdh.computeSecret(Buffer.from(asnPublicKey.publicKey));

    return new Uint8Array(bits).buffer.slice(0, length >> 3);
  }

  public static async exportKey(format: types.KeyFormat, key: CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "pkcs8":
      case "spki":
        return new Uint8Array(key.data).buffer;
      case "raw": {
        const publicKeyInfo = AsnParser.parse(key.data, schema.PublicKeyInfo);
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
          const asnKey = JsonParser.fromJSON(keyData, { targetSchema: schema.EcPrivateKey });
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          const asnKey = JsonParser.fromJSON(keyData, { targetSchema: schema.EcPublicKey });
          return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
        }
      }
      case "raw": {
        const asnKey = new schema.EcPublicKey(keyData as ArrayBuffer);
        return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
      }
      case "spki": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), schema.PublicKeyInfo);
        const asnKey = new schema.EcPublicKey(keyInfo.publicKey);
        this.assertKeyParameters(keyInfo.publicKeyAlgorithm.parameters, algorithm.namedCurve);
        return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), schema.PrivateKeyInfo);
        const asnKey = AsnParser.parse(keyInfo.privateKey, schema.EcPrivateKey);
        this.assertKeyParameters(keyInfo.privateKeyAlgorithm.parameters, algorithm.namedCurve);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  protected static assertKeyParameters(parameters: ArrayBuffer | null | undefined, namedCurve: string) {
    if (!parameters) {
      throw new core.CryptoError("Key info doesn't have required parameters");
    }

    let namedCurveIdentifier = "";
    try {
      namedCurveIdentifier = AsnParser.parse(parameters, schema.ObjectIdentifier).value;
    } catch (e) {
      throw new core.CryptoError("Cannot read key info parameters");
    }

    if (getOidByNamedCurve(namedCurve) !== namedCurveIdentifier) {
      throw new core.CryptoError("Key info parameter doesn't match to named curve");
    }
  }

  protected static async importPrivateKey(asnKey: schema.EcPrivateKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const keyInfo = new schema.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(new schema.ObjectIdentifier(getOidByNamedCurve(algorithm.namedCurve)));
    keyInfo.privateKey = AsnSerializer.serialize(asnKey);

    const key = new EcPrivateKey();
    key.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as types.EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  protected static async importPublicKey(asnKey: schema.EcPublicKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const keyInfo = new schema.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    const namedCurve = getOidByNamedCurve(algorithm.namedCurve);
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(new schema.ObjectIdentifier(namedCurve));
    keyInfo.publicKey = asnKey.value;

    const key = new EcPublicKey();
    key.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as types.EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  private static getOpenSSLNamedCurve(curve: string) {
    switch (curve.toUpperCase()) {
      case "P-256":
        return "prime256v1";
      case "K-256":
        return "secp256k1";
      case "P-384":
        return "secp384r1";
      case "P-521":
        return "secp521r1";
      default:
        return curve;
    }
  }

}
