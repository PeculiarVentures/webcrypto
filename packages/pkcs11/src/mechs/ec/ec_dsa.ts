import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

import { CryptoKey } from "../../key";
import { IContainer, ISessionContainer, Pkcs11EcKeyGenParams, Pkcs11EcKeyImportParams } from "../../types";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdsaProvider extends core.EcdsaProvider implements IContainer {

  public override namedCurves = core.EcCurves.names;

  public override usages: types.ProviderKeyPairUsage = {
    privateKey: ["sign", "deriveKey", "deriveBits"],
    publicKey: ["verify"],
  };

  public crypto: EcCrypto;

  constructor(public container: ISessionContainer) {
    super();

    this.crypto = new EcCrypto(container);
  }

  public override async onGenerateKey(algorithm: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public override async onSign(algorithm: types.EcdsaParams, key: EcCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = this.crypto.getAlgorithm(mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = this.crypto.prepareData((algorithm.hash as types.Algorithm).name, buf);
      }
      this.container.session.createSign(mechanism, key.key).once(buf, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  public override async onVerify(algorithm: types.EcdsaParams, key: EcCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = this.crypto.getAlgorithm(mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = this.crypto.prepareData((algorithm.hash as types.Algorithm).name, buf);
      }
      this.container.session.createVerify(mechanism, key.key).once(buf, Buffer.from(signature), (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(data2);
        }
      });
    });
  }

  public override async onExportKey(format: types.KeyFormat, key: EcCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public override async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcCryptoKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  protected wc2pk11(alg: types.EcdsaParams, keyAlg: types.KeyAlgorithm): { name: string, params: null; } {
    let algName: string;
    const hashAlg = (alg.hash as types.Algorithm).name.toUpperCase();
    switch (hashAlg) {
      case "SHA-1":
        algName = "ECDSA_SHA1";
        break;
      case "SHA-224":
        algName = "ECDSA_SHA224";
        break;
      case "SHA-256":
        algName = "ECDSA_SHA256";
        break;
      case "SHA-384":
        algName = "ECDSA_SHA384";
        break;
      case "SHA-512":
        algName = "ECDSA_SHA512";
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${hashAlg}'`);
    }
    return { name: algName, params: null };
  }

}
