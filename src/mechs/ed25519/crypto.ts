import crypto from "crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Ed25519CryptoKey } from "./crypto_key";
import { Ed25519PrivateKey } from "./private_key";
import { Ed25519PublicKey } from "./public_key";
import { CryptoKey } from "../../keys";

export class Ed25519Crypto {
  public static privateKeyUsages: KeyUsage[] = ["sign", "deriveBits", "deriveKey"];
  public static publicKeyUsages: KeyUsage[] = ["verify"];

  public static async generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const type = algorithm.name.toLowerCase() as "ed25519";
    const keys = crypto.generateKeyPairSync(type, {
      publicKeyEncoding: {
        format: "pem",
        type: "spki",
      },
      privateKeyEncoding: {
        format: "pem",
        type: "pkcs8",
      },
    });

    const keyAlg = {
      name: type === "ed25519" ? "Ed25519" : "X25519",
    };
    const privateKeyUsages = keyUsages.filter((usage) => this.privateKeyUsages.includes(usage));
    const publicKeyUsages = keyUsages.filter((usage) => this.publicKeyUsages.includes(usage));
    return {
      privateKey: new Ed25519PrivateKey(keyAlg, extractable, privateKeyUsages, keys.privateKey),
      publicKey: new Ed25519PublicKey(keyAlg, true, publicKeyUsages, keys.publicKey),
    };
  }

  public static async sign(algorithm: Algorithm, key: Ed25519PrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    const signature = crypto.sign(null, Buffer.from(data), key.data);

    return core.BufferSourceConverter.toArrayBuffer(signature);
  }

  public static async verify(algorithm: Algorithm, key: Ed25519PublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    return crypto.verify(null, Buffer.from(data), key.data, signature);
  }

  public static async exportKey(format: KeyFormat, key: Ed25519CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format) {
      case "jwk":
        return key.toJWK();
      case "pkcs8": {
        return core.PemConverter.toArrayBuffer(key.data.toString());
      }
      case "spki": {
        return core.PemConverter.toArrayBuffer(key.data.toString());
      }
      case "raw": {
        const jwk = key.toJWK();
        return Convert.FromBase64Url(jwk.x!);
      }
      default:
        return Promise.reject(new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'"));
    }
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format) {
      case "jwk": {
        const jwk = keyData as JsonWebKey;
        if (jwk.d) {
          // private key
          const privateData = new core.asn1.EdPrivateKey();
          privateData.value = core.BufferSourceConverter.toArrayBuffer(Buffer.from(jwk.d, "base64url"));
          const pkcs8 = new core.asn1.PrivateKeyInfo();
          pkcs8.privateKeyAlgorithm.algorithm = algorithm.name.toLowerCase() === "ed25519"
            ? core.asn1.idEd25519
            : core.asn1.idX25519;
          pkcs8.privateKey = AsnConvert.serialize(privateData);
          const raw = AsnConvert.serialize(pkcs8);
          const pem = core.PemConverter.fromBufferSource(raw, "PRIVATE KEY");
          return new Ed25519PrivateKey(algorithm, extractable, keyUsages, pem);
        } else if (jwk.x) {
          // public key
          const pubKey = crypto.createPublicKey({
            format: "jwk",
            key: jwk as crypto.JsonWebKey,
          });
          const pem = pubKey.export({ format: "pem", type: "spki" }) as string;
          return new Ed25519PublicKey(algorithm, extractable, keyUsages, pem);
        } else {
          throw new core.OperationError("keyData: Cannot import JWK. 'd' or 'x' must be presented");
        }
      }
      case "pkcs8": {
        const pem = core.PemConverter.fromBufferSource(keyData as ArrayBuffer, "PRIVATE KEY");
        return new Ed25519PrivateKey(algorithm, extractable, keyUsages, pem);
      }
      case "spki": {
        const pem = core.PemConverter.fromBufferSource(keyData as ArrayBuffer, "PUBLIC KEY");
        return new Ed25519PublicKey(algorithm, extractable, keyUsages, pem);
      }
      case "raw": {
        const raw = keyData as ArrayBuffer;
        const key = crypto.createPublicKey({
          format: "jwk",
          key: {
            kty: "OKP",
            crv: algorithm.name.toLowerCase() === "ed25519" ? "Ed25519" : "X25519",
            x: Convert.ToBase64Url(raw),
          },
        });
        const pem = key.export({ format: "pem", type: "spki" }) as string;
        return new Ed25519PublicKey(algorithm, extractable, keyUsages, pem);
      }
      default:
        return Promise.reject(new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'"));
    }
  }
}
