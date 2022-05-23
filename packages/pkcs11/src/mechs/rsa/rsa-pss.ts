import * as graphene from "graphene-pk11";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

import { CryptoKey } from "../../key";
import { IContainer, ISessionContainer } from "../../types";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaPssProvider extends core.RsaPssProvider implements IContainer {

  public override usages: types.ProviderKeyPairUsage = {
    privateKey: ["sign", "decrypt", "unwrapKey"],
    publicKey: ["verify", "encrypt", "wrapKey"],
  };
  public crypto: RsaCrypto;

  constructor(public container: ISessionContainer) {
    super();

    this.crypto = new RsaCrypto(container);
  }

  public async onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: types.RsaPssParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as types.RsaHashedKeyAlgorithm);
      mechanism.name = this.crypto.getAlgorithm(this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS_PSS") {
        buf = this.crypto.prepareData((key as any).algorithm.hash.name, buf);
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

  public async onVerify(algorithm: types.RsaPssParams, key: RsaCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as types.RsaHashedKeyAlgorithm);
      mechanism.name = this.crypto.getAlgorithm(this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS_PSS") {
        buf = this.crypto.prepareData((key as any).algorithm.hash.name, buf);
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

  public async onExportKey(format: types.KeyFormat, key: RsaCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: types.RsaPssParams, keyAlg: types.RsaHashedKeyAlgorithm): { name: string, params: graphene.IParams; } {
    let mech: string;
    let param: graphene.RsaPssParams;
    const saltLen = alg.saltLength;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        mech = "SHA1_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA1, graphene.RsaMgf.MGF1_SHA1, saltLen);
        break;
      case "SHA-224":
        mech = "SHA224_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA224, graphene.RsaMgf.MGF1_SHA224, saltLen);
        break;
      case "SHA-256":
        mech = "SHA256_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA256, graphene.RsaMgf.MGF1_SHA256, saltLen);
        break;
      case "SHA-384":
        mech = "SHA384_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA384, graphene.RsaMgf.MGF1_SHA384, saltLen);
        break;
      case "SHA-512":
        mech = "SHA512_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA512, graphene.RsaMgf.MGF1_SHA512, saltLen);
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    return { name: mech, params: param };
  }

}
