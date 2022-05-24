import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as elliptic from "elliptic";
import { Convert } from "pvtsutils";
import { CryptoKey } from "../../key";
import { nativeCrypto } from "../../native";
import { b2a } from "../ec";
import { getOidByNamedCurve } from "./helper";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static checkLib() {
    if (typeof (elliptic) === "undefined") {
      throw new core.OperationError("Cannot implement EC mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/elliptic.js' script to your project");
    }
  }

  public static concat(...buf: Uint8Array[]) {
    const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
    let offset = 0;
    buf.forEach((item, index) => {
      for (let i = 0; i < item.length; i++) {
        res[offset + i] = item[i];
      }
      offset += item.length;
    });
    return res;
  }

  public static async generateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    this.checkLib();

    // const curve = algorithm.namedCurve.toLowerCase() === "x25519" ? "curve25519" : "ed25519"; // "x25519" | "ed25519"
    const curve = "ed25519";
    let edKey: EllipticJS.EllipticKeyPair;
    if (curve === "ed25519") {
      const raw = nativeCrypto.getRandomValues(new Uint8Array(32));
      const eddsa = new elliptic.eddsa(curve);
      edKey = eddsa.keyFromSecret(raw);
    } else {
      edKey = elliptic.ec(curve).genKeyPair();
      edKey.getPublic(); // Fills internal `pub` field
    }

    // set key params
    const prvKey = new EdPrivateKey(
      algorithm,
      extractable,
      keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1),
      edKey,
    );
    const pubKey = new EdPublicKey(
      algorithm,
      true,
      keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1),
      edKey,
    );

    return {
      privateKey: prvKey,
      publicKey: pubKey,
    };
  }

  public static async sign(algorithm: types.Algorithm, key: EdPrivateKey, data: Uint8Array): Promise<ArrayBuffer> {
    this.checkLib();

    const array = b2a(data);
    const signature = key.data.sign(array).toHex();

    return Convert.FromHex(signature);
  }

  public static async verify(algorithm: types.EcdsaParams, key: EdPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    this.checkLib();

    const array = b2a(data);
    const ok = key.data.verify(array, Convert.ToHex(signature));
    return ok;
  }

  public static async deriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: EdPrivateKey, length: number): Promise<ArrayBuffer> {
    this.checkLib();

    const key = new Uint8Array(Convert.FromHex(baseKey.data.getSecret("hex")));
    // key[0] &= 248;
    // key[31] &= 127;
    // key[31] |= 64;
    // key.reverse();

    // @ts-ignore
    const ecdh = new elliptic.ec("curve25519");
    const privateKey = ecdh.keyFromPrivate(Convert.ToHex(key), "hex");

    const publicHex = (algorithm.public as EdPublicKey).data.getPublic("hex") as string;
    const publicView = new Uint8Array(Convert.FromHex(publicHex));
    // publicView.reverse();
    // const publicKey = ecdh.keyFromPublic(Convert.ToHex(publicView), "hex").getPublic();
    const publicKey = (algorithm.public as EdPublicKey).data.getPublic();
    const shared = privateKey.derive(publicKey);
    let array = new Uint8Array(shared.toArray());

    // Padding
    let len = array.length;
    len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
    if (array.length < len) {
      array = EdCrypto.concat(new Uint8Array(len - array.length), array);
    }
    const buf = array.slice(0, length / 8).buffer;
    return buf;
  }

  public static async exportKey(format: types.KeyFormat, key: EdPrivateKey | EdPublicKey): Promise<types.JsonWebKey | ArrayBuffer> {
    this.checkLib();

    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "pkcs8": {
        // const raw = Convert.FromHex(/^x/i.test(key.algorithm.namedCurve)
        //   ? key.data.getPrivate("hex")
        //   : key.data.getSecret("hex"));
        const raw = Convert.FromHex(key.data.getSecret("hex"));
        const keyInfo = new core.asn1.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = getOidByNamedCurve(key.algorithm.namedCurve);
        keyInfo.privateKey = AsnConvert.serialize(new OctetString(raw));

        return AsnConvert.serialize(keyInfo);
      }
      case "spki": {
        const raw = Convert.FromHex(key.data.getPublic("hex"));
        const keyInfo = new core.asn1.PublicKeyInfo();
        keyInfo.publicKeyAlgorithm.algorithm = getOidByNamedCurve(key.algorithm.namedCurve);
        keyInfo.publicKey = raw;

        return AsnConvert.serialize(keyInfo);
      }
      case "raw": {
        return Convert.FromHex(key.data.getPublic("hex"));
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    this.checkLib();

    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk = keyData as types.JsonWebKey;
        if (jwk.d) {
          const asnKey = JsonParser.fromJSON(keyData, { targetSchema: core.asn1.CurvePrivateKey });
          return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
        } else {
          if (!jwk.x) {
            throw new TypeError("keyData: Cannot get required 'x' field");
          }
          return this.importPublicKey(Convert.FromBase64Url(jwk.x), algorithm, extractable, keyUsages);
        }
      }
      case "raw": {
        return this.importPublicKey(keyData as ArrayBuffer, algorithm, extractable, keyUsages);
      }
      case "spki": {
        const keyInfo = AsnConvert.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PublicKeyInfo);
        return this.importPublicKey(keyInfo.publicKey, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const keyInfo = AsnConvert.parse(new Uint8Array(keyData as ArrayBuffer), core.asn1.PrivateKeyInfo);
        const asnKey = AsnConvert.parse(keyInfo.privateKey, core.asn1.CurvePrivateKey);
        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  protected static importPrivateKey(asnKey: core.asn1.CurvePrivateKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const key = new EdPrivateKey(
      Object.assign({}, algorithm),
      extractable,
      keyUsages, null as any); // key.data inits in key.fromJSON

    key.fromJSON({
      crv: algorithm.namedCurve,
      d: Convert.ToBase64Url(asnKey.d),
    });

    return key;
  }

  protected static async importPublicKey(asnKey: ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]) {
    const key = new EdPublicKey(
      Object.assign({}, algorithm),
      extractable,
      keyUsages, null as any); // key.data inits in key.fromJSON

    key.fromJSON({
      crv: algorithm.namedCurve,
      x: Convert.ToBase64Url(asnKey),
    });

    return key;
  }

}
