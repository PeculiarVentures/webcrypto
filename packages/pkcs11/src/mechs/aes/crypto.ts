import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";

import { CryptoKey } from "../../key";
import { GUID, prepareData } from "../../utils";
import { IContainer, ISessionContainer, Pkcs11AesKeyAlgorithm, Pkcs11AesKeyGenParams, Pkcs11KeyImportParams } from "../../types";

import { AesCryptoKey } from "./key";

export class AesCrypto implements IContainer {

  constructor(public container: ISessionContainer) {
  }

  public async generateKey(algorithm: Pkcs11AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      const template = this.container.templateBuilder.build({
        action: "generate",
        type: "secret",
        attributes: {
          id: GUID(),
          label: algorithm.label || `AES-${algorithm.length}`,
          token: algorithm.token,
          sensitive: algorithm.sensitive,
          extractable,
          usages: keyUsages,
        },
      });
      template.keyType = graphene.KeyType.AES;
      template.valueLen = algorithm.length >> 3;

      // PKCS11 generation
      this.container.session.generateKey(graphene.KeyGenMechanism.AES, template, (err, aesKey) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Aes: Can not generate new key\n${err.message}`));
          } else {
            if (!aesKey) {
              throw new Error("Cannot get key from callback function");
            }
            resolve(new AesCryptoKey(aesKey, algorithm));
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public async exportKey(format: string, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    const template = key.key.getAttribute({ value: null, valueLen: null });
    switch (format.toLowerCase()) {
      case "jwk":
        const aes: string = /AES-(\w+)/.exec(key.algorithm.name!)![1];
        const jwk: types.JsonWebKey = {
          kty: "oct",
          k: Convert.ToBase64Url(template.value!),
          alg: `A${template.valueLen! * 8}${aes}`,
          ext: true,
          key_ops: key.usages,
        };
        return jwk;
      case "raw":
        return new Uint8Array(template.value!).buffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public async importKey(format: string, keyData: types.JsonWebKey | ArrayBuffer, algorithm: Pkcs11KeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    // get key value
    let value: ArrayBuffer;

    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = keyData as types.JsonWebKey;
        if (!jwk.k) {
          throw new core.OperationError("jwk.k: Cannot get required property");
        }
        keyData = Convert.FromBase64Url(jwk.k);
      case "raw":
        value = keyData as ArrayBuffer;
        switch (value.byteLength) {
          case 16:
          case 24:
          case 32:
            break;
          default:
            throw new core.OperationError("keyData: Is wrong key length");
        }
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    // prepare key algorithm
    const aesAlg: Pkcs11AesKeyAlgorithm = {
      ...AesCryptoKey.defaultKeyAlgorithm(),
      ...algorithm,
      length: value.byteLength * 8,
    };
    const template: graphene.ITemplate = this.container.templateBuilder.build({
      action: "import",
      type: "secret",
      attributes: {
        id: GUID(),
        label: algorithm.label || `AES-${aesAlg.length}`,
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        extractable,
        usages: keyUsages,
      },
    });
    template.keyType = graphene.KeyType.AES;
    template.value = Buffer.from(value);

    // create session object
    const sessionObject = this.container.session.create(template);
    const key = new AesCryptoKey(sessionObject.toType<graphene.SecretKey>(), aesAlg);
    return key;
  }

  public async encrypt(padding: boolean, algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // add padding if needed
    if (padding) {
      const blockLength = 16;
      const mod = blockLength - (data.byteLength % blockLength);
      const pad = Buffer.alloc(mod);
      pad.fill(mod);
      data = Buffer.concat([Buffer.from(data), pad]);
    }

    return new Promise<ArrayBuffer>((resolve, reject) => {
      const enc = Buffer.alloc(this.getOutputBufferSize(key.algorithm, true, data.byteLength));
      const mechanism = this.wc2pk11(algorithm);
      this.container.session.createCipher(mechanism, key.key)
        .once(Buffer.from(data), enc, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(new Uint8Array(data2).buffer);
          }
        });
    });
  }

  public async decrypt(padding: boolean, algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const dec = await new Promise<Buffer>((resolve, reject) => {
      const buf = Buffer.alloc(this.getOutputBufferSize(key.algorithm, false, data.byteLength));
      const mechanism = this.wc2pk11(algorithm);
      this.container.session.createDecipher(mechanism, key.key)
        .once(Buffer.from(data), buf, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(data2);
          }
        });
    });
    if (padding) {
      // Remove padding
      const paddingLength = dec[dec.length - 1];

      const res = new Uint8Array(dec.slice(0, dec.length - paddingLength));
      return res.buffer;
    } else {
      return new Uint8Array(dec).buffer;
    }
  }

  protected isAesGCM(algorithm: types.Algorithm): algorithm is types.AesGcmParams {
    return algorithm.name.toUpperCase() === "AES-GCM";
  }

  protected isAesCBC(algorithm: types.Algorithm): algorithm is types.AesCbcParams {
    return algorithm.name.toUpperCase() === "AES-CBC";
  }

  protected isAesECB(algorithm: types.Algorithm): algorithm is types.Algorithm {
    return algorithm.name.toUpperCase() === "AES-ECB";
  }

  protected wc2pk11(algorithm: types.Algorithm) {
    const session = this.container.session;
    if (this.isAesGCM(algorithm)) {
      const aad = algorithm.additionalData ? prepareData(algorithm.additionalData) : undefined;
      let AesGcmParamsClass = graphene.AesGcmParams;
      if (session.slot.module.cryptokiVersion.major >= 2 &&
        session.slot.module.cryptokiVersion.minor >= 40) {
        AesGcmParamsClass = graphene.AesGcm240Params;
      }
      const params = new AesGcmParamsClass(prepareData(algorithm.iv), aad, algorithm.tagLength || 128);
      return { name: "AES_GCM", params };
    } else if (this.isAesCBC(algorithm)) {
      return { name: "AES_CBC_PAD", params: prepareData(algorithm.iv) };
    } else if (this.isAesECB(algorithm)) {
      return { name: "AES_ECB", params: null };
    } else {
      throw new core.OperationError("Unrecognized algorithm name");
    }
  }

  /**
   * Returns a size of output buffer of enc/dec operation
   * @param keyAlg key algorithm
   * @param enc type of operation
   * `true` - encryption operation
   * `false` - decryption operation
   * @param dataSize size of incoming data
   */
  protected getOutputBufferSize(keyAlg: Pkcs11AesKeyAlgorithm, enc: boolean, dataSize: number): number {
    const len = keyAlg.length >> 3;
    if (enc) {
      return (Math.ceil(dataSize / len) * len) + len;
    } else {
      return dataSize;
    }
  }

}
