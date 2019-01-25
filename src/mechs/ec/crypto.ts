import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import crypto from "crypto";
import * as core from "webcrypto-core";
import * as asn from "../../asn";
import { ObjectIdentifier } from "../../asn";
import { CryptoKey } from "../../keys";
import { getOidByNamedCurve } from "./helper";
import { EcPrivateKey } from "./private_key";
import { EcPublicKey } from "./public_key";

export class EcCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const privateKey = new EcPrivateKey();
    privateKey.algorithm = algorithm;
    privateKey.extractable = extractable;
    privateKey.usages = keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1);

    const publicKey = new EcPublicKey();
    publicKey.algorithm = algorithm;
    publicKey.extractable = true;
    publicKey.usages = keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1);

    // @ts-ignore NodeJs d.ts error
    const keys = crypto.generateKeyPairSync("ec", {
      namedCurve: this.getOpenSSLNamedCurve(algorithm.namedCurve),
      publicKeyEncoding: {
        format: "der",
        type: "spki",
      },
      // @ts-ignore NodeJs d.ts error
      privateKeyEncoding: {
        format: "der",
        type: "pkcs8",
      },
    });

    privateKey.data = keys.privateKey;
    publicKey.data = keys.publicKey;

    const res: CryptoKeyPair = {
      privateKey,
      publicKey,
    };

    return res;
  }

  public static async sign(algorithm: EcdsaParams, key: EcPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    const cryptoAlg = (algorithm.hash as Algorithm).name.replace("-", "");
    const signer = crypto.createSign(cryptoAlg);
    signer.update(Buffer.from(data));

    const options = {
      key: `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`,
    };

    const signature = signer.sign(options);
    const ecSignature = AsnParser.parse(signature, asn.EcDsaSignature);

    return new Uint8Array(Buffer.concat([
      Buffer.from(ecSignature.r),
      Buffer.from(ecSignature.s),
    ])).buffer;
  }

  public static async verify(algorithm: EcdsaParams, key: EcPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    const cryptoAlg = (algorithm.hash as Algorithm).name.replace("-", "");
    const signer = crypto.createVerify(cryptoAlg);
    signer.update(Buffer.from(data));

    const options = {
      key: `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`,
    };

    const ecSignature = new asn.EcDsaSignature();
    const size = signature.length / 2;
    ecSignature.r = signature.buffer.slice(0, size);
    ecSignature.s = signature.buffer.slice(size, size + size);

    const ok = signer.verify(options, Buffer.from(AsnSerializer.serialize(ecSignature)));
    return ok;
  }

  public static async deriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    const cryptoAlg = this.getOpenSSLNamedCurve((baseKey.algorithm as EcKeyAlgorithm).namedCurve);

    const ecdh = crypto.createECDH(cryptoAlg);
    const asnPrivateKey = AsnParser.parse(baseKey.data, asn.PrivateKeyInfo);
    const asnEcPrivateKey = AsnParser.parse(asnPrivateKey.privateKey, asn.EcPrivateKey);
    ecdh.setPrivateKey(Buffer.from(asnEcPrivateKey.privateKey));

    const asnPublicKey = AsnParser.parse((algorithm.public as CryptoKey).data, asn.PublicKeyInfo);
    const bits = ecdh.computeSecret(Buffer.from(asnPublicKey.publicKey));

    return new Uint8Array(bits).buffer.slice(0, length >> 3);
  }

  public static async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "pkcs8":
      case "spki":
        return new Uint8Array(key.data).buffer;
      case "raw":
        const publicKeyInfo = AsnParser.parse(key.data, asn.PublicKeyInfo);
        return publicKeyInfo.publicKey;
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = keyData as JsonWebKey;
        if (jwk.d) {
          const asnKey = JsonParser.fromJSON(keyData, asn.EcPrivateKey);
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          const asnKey = JsonParser.fromJSON(keyData, asn.EcPublicKey);
          return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
        }
      case "raw": {
        const asnKey = new asn.EcPublicKey(keyData as ArrayBuffer);
        return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
      }
      case "spki": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), asn.PublicKeyInfo);
        const asnKey = new asn.EcPublicKey(keyInfo.publicKey);
        return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), asn.PrivateKeyInfo);
        const asnKey = AsnParser.parse(keyInfo.privateKey, asn.EcPrivateKey);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  protected static async importPrivateKey(asnKey: asn.EcPrivateKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const keyInfo = new asn.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(new ObjectIdentifier(getOidByNamedCurve(algorithm.namedCurve)));
    keyInfo.privateKey = AsnSerializer.serialize(asnKey);

    const key = new EcPrivateKey();
    key.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as EcKeyAlgorithm;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  protected static async importPublicKey(asnKey: asn.EcPublicKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const keyInfo = new asn.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(new ObjectIdentifier(getOidByNamedCurve(algorithm.namedCurve)));
    keyInfo.publicKey = asnKey.value;

    const key = new EcPublicKey();
    key.data = Buffer.from(AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as EcKeyAlgorithm;
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
        throw new core.OperationError(`Cannot convert WebCrypto named curve to NodeJs. Unknown name '${curve}'`);
    }
  }

}
