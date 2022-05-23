import * as asn1Schema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { CryptoKey } from "../../keys";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";

interface INodeCryptoSignOptions {
  key: string;
  passphrase?: string;
  padding?: number;
  saltLength?: number;
}

export class RsaCrypto {

  public static publicKeyUsages = ["verify", "encrypt", "wrapKey"];
  public static privateKeyUsages = ["sign", "decrypt", "unwrapKey"];

  public static async generateKey(algorithm: types.RsaHashedKeyGenParams | types.RsaKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const privateKey = new RsaPrivateKey();
    privateKey.algorithm = algorithm as types.RsaHashedKeyAlgorithm;
    privateKey.extractable = extractable;
    privateKey.usages = keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1);

    const publicKey = new RsaPublicKey();
    publicKey.algorithm = algorithm as types.RsaHashedKeyAlgorithm;
    publicKey.extractable = true;
    publicKey.usages = keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1);

    const publicExponent = Buffer.concat([
      Buffer.alloc(4 - algorithm.publicExponent.byteLength, 0),
      Buffer.from(algorithm.publicExponent),
    ]).readInt32BE(0);

    const keys = crypto.generateKeyPairSync("rsa", {
      modulusLength: algorithm.modulusLength,
      publicExponent,
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

  public static async exportKey(format: types.KeyFormat, key: CryptoKey): Promise<crypto.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return jsonSchema.JsonSerializer.toJSON(key);
      case "pkcs8":
      case "spki":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk = keyData as types.JsonWebKey;
        if (jwk.d) {
          const asnKey = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: schema.RsaPrivateKey });
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          const asnKey = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: schema.RsaPublicKey });
          return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
        }
      }
      case "spki": {
        const keyInfo = asn1Schema.AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), schema.PublicKeyInfo);
        const asnKey = asn1Schema.AsnParser.parse(keyInfo.publicKey, schema.RsaPublicKey);
        return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = asn1Schema.AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), schema.PrivateKeyInfo);
        const asnKey = asn1Schema.AsnParser.parse(keyInfo.privateKey, schema.RsaPrivateKey);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public static async sign(algorithm: types.Algorithm, key: RsaPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-PSS":
      case "RSASSA-PKCS1-V1_5":
        return this.signRsa(algorithm, key, data);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async verify(algorithm: types.Algorithm, key: RsaPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-PSS":
      case "RSASSA-PKCS1-V1_5":
        return this.verifySSA(algorithm, key, data, signature);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async encrypt(algorithm: types.RsaOaepParams, key: RsaPublicKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP":
        return this.encryptOAEP(algorithm, key, data);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  public static async decrypt(algorithm: types.RsaOaepParams, key: RsaPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP":
        return this.decryptOAEP(algorithm, key, data);
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  protected static importPrivateKey(asnKey: schema.RsaPrivateKey, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const keyInfo = new schema.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;
    keyInfo.privateKey = asn1Schema.AsnSerializer.serialize(asnKey);

    const key = new RsaPrivateKey();
    key.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as types.RsaHashedKeyAlgorithm;
    key.algorithm.publicExponent = new Uint8Array(asnKey.publicExponent);
    key.algorithm.modulusLength = asnKey.modulus.byteLength << 3;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  protected static importPublicKey(asnKey: schema.RsaPublicKey, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const keyInfo = new schema.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = asn1Schema.AsnSerializer.serialize(asnKey);

    const key = new RsaPublicKey();
    key.data = Buffer.from(asn1Schema.AsnSerializer.serialize(keyInfo));

    key.algorithm = Object.assign({}, algorithm) as types.RsaHashedKeyAlgorithm;
    key.algorithm.publicExponent = new Uint8Array(asnKey.publicExponent);
    key.algorithm.modulusLength = asnKey.modulus.byteLength << 3;
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  protected static getCryptoAlgorithm(alg: types.RsaHashedKeyAlgorithm) {
    switch (alg.hash.name.toUpperCase()) {
      case "SHA-1":
        return "RSA-SHA1";
      case "SHA-256":
        return "RSA-SHA256";
      case "SHA-384":
        return "RSA-SHA384";
      case "SHA-512":
        return "RSA-SHA512";
      case "SHA3-256":
        return "RSA-SHA3-256";
      case "SHA3-384":
        return "RSA-SHA3-384";
      case "SHA3-512":
        return "RSA-SHA3-512";
      default:
        throw new core.OperationError("algorithm.hash: Is not recognized");
    }
  }

  protected static signRsa(algorithm: types.Algorithm, key: RsaPrivateKey, data: Uint8Array) {
    const cryptoAlg = this.getCryptoAlgorithm(key.algorithm);
    const signer = crypto.createSign(cryptoAlg);
    signer.update(Buffer.from(data));

    if (!key.pem) {
      key.pem = `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`;
    }
    const options: INodeCryptoSignOptions = {
      key: key.pem,
    };
    if (algorithm.name.toUpperCase() === "RSA-PSS") {
      options.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
      options.saltLength = (algorithm as types.RsaPssParams).saltLength;
    }

    const signature = signer.sign(options);
    return new Uint8Array(signature).buffer;
  }

  protected static verifySSA(algorithm: types.Algorithm, key: RsaPublicKey, data: Uint8Array, signature: Uint8Array) {
    const cryptoAlg = this.getCryptoAlgorithm(key.algorithm);
    const signer = crypto.createVerify(cryptoAlg);
    signer.update(Buffer.from(data));

    if (!key.pem) {
      key.pem = `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`;
    }
    const options: INodeCryptoSignOptions = {
      key: key.pem,
    };
    if (algorithm.name.toUpperCase() === "RSA-PSS") {
      options.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
      options.saltLength = (algorithm as types.RsaPssParams).saltLength;
    }

    const ok = signer.verify(options, signature);
    return ok;
  }

  protected static encryptOAEP(algorithm: types.RsaOaepParams, key: RsaPublicKey, data: Uint8Array) {
    const options: crypto.RsaPublicKey = {
      key: `-----BEGIN PUBLIC KEY-----\n${key.data.toString("base64")}\n-----END PUBLIC KEY-----`,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    };
    if (algorithm.label) {
      // nothing
    }

    return new Uint8Array(crypto.publicEncrypt(options, data)).buffer;
  }

  protected static decryptOAEP(algorithm: types.RsaOaepParams, key: RsaPrivateKey, data: Uint8Array) {
    const options: crypto.RsaPrivateKey = {
      key: `-----BEGIN PRIVATE KEY-----\n${key.data.toString("base64")}\n-----END PRIVATE KEY-----`,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    };
    if (algorithm.label) {
      // nothing
    }

    return new Uint8Array(crypto.privateDecrypt(options, data)).buffer;
  }

}
