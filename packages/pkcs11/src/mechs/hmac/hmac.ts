import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";

import { CryptoKey } from "../../key";
import {
  IContainer, ISessionContainer, ITemplateBuildParameters, ITemplate,
  Pkcs11HmacKeyAlgorithm, Pkcs11HmacKeyGenParams, Pkcs11HmacKeyImportParams,
} from "../../types";
import { GUID } from "../../utils";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider implements IContainer {

  constructor(public container: ISessionContainer) {
    super();
  }

  public async onGenerateKey(algorithm: Pkcs11HmacKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      const length = (algorithm.length || this.getDefaultLength((algorithm.hash as types.Algorithm).name)) >> 3 << 3;
      algorithm = { ...algorithm, name: this.name, length };

      const template = this.createTemplate({
        action: "generate",
        type: "secret",
        attributes: {
          token: algorithm.token,
          sensitive: algorithm.sensitive,
          label: algorithm.label,
          extractable,
          usages: keyUsages
        },
      });
      template.valueLen = length >> 3;

      // PKCS11 generation
      this.container.session.generateKey(graphene.KeyGenMechanism.GENERIC_SECRET, template, (err, key) => {
        try {
          if (err) {
            reject(new core.CryptoError(`HMAC: Cannot generate new key\n${err.message}`));
          } else {
            if (!key) {
              throw new Error("Cannot get key from callback function");
            }
            resolve(new HmacCryptoKey(key, algorithm));
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public override async onSign(algorithm: types.Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      this.container.session.createSign(mechanism, key.key).once(Buffer.from(data), (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  public override async onVerify(algorithm: types.Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      this.container.session.createVerify(mechanism, key.key).once(Buffer.from(data), Buffer.from(signature), (err, ok) => {
        if (err) {
          reject(err);
        } else {
          resolve(ok);
        }
      });
    });
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: Pkcs11HmacKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    // get key value
    let value: ArrayBuffer;

    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = keyData as types.JsonWebKey;
        if (!jwk.k) {
          throw new core.OperationError("jwk.k: Cannot get required property");
        }
        keyData = pvtsutils.Convert.FromBase64Url(jwk.k);
      case "raw":
        value = keyData as ArrayBuffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
    // prepare key algorithm
    const hmacAlg = {
      ...algorithm,
      name: this.name,
      length: value.byteLength * 8 || this.getDefaultLength((algorithm as any).hash.name),
    } as Pkcs11HmacKeyAlgorithm;
    const template: graphene.ITemplate = this.createTemplate({
      action: "import",
      type: "secret",
      attributes: {
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        label: algorithm.label,
        extractable,
        usages: keyUsages
      },
    });
    template.value = Buffer.from(value);

    // create session object
    const sessionObject = this.container.session.create(template);
    const key = new HmacCryptoKey(sessionObject.toType<graphene.SecretKey>(), hmacAlg);
    return key;
  }

  public async onExportKey(format: types.KeyFormat, key: HmacCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    const template = key.key.getAttribute({ value: null });
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk: types.JsonWebKey = {
          kty: "oct",
          k: pvtsutils.Convert.ToBase64Url(template.value!),
          alg: `HS${key.algorithm.hash.name.replace("SHA-", "")}`,
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

  public override checkCryptoKey(key: CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

  protected createTemplate(params: ITemplateBuildParameters): ITemplate {
    const template = this.container.templateBuilder.build({
      ...params,
      attributes: {
        ...params.attributes,
        id: GUID(),
        label: params.attributes.label || "HMAC",
      },
    });

    template.keyType = graphene.KeyType.GENERIC_SECRET;

    return template;
  }

  protected wc2pk11(alg: types.Algorithm, keyAlg: types.HmacKeyAlgorithm): graphene.IAlgorithm {
    let res: string;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        res = "SHA_1_HMAC";
        break;
      case "SHA-224":
        res = "SHA224_HMAC";
        break;
      case "SHA-256":
        res = "SHA256_HMAC";
        break;
      case "SHA-384":
        res = "SHA384_HMAC";
        break;
      case "SHA-512":
        res = "SHA512_HMAC";
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    return { name: res, params: null };
  }

}
