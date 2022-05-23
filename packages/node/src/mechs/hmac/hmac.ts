import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { ShaCrypto } from "../sha";
import { setCryptoKey, getCryptoKey } from "../storage";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  public async onGenerateKey(algorithm: types.PreparedHashedAlgorithm<types.HmacKeyGenParams>, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    const length = (algorithm.length || this.getDefaultLength(algorithm.hash.name)) >> 3 << 3;
    const key = new HmacCryptoKey();
    key.algorithm = {
      ...algorithm as any,
      length,
      name: this.name,
    };
    key.extractable = extractable;
    key.usages = keyUsages;
    key.data = crypto.randomBytes(length >> 3);

    return setCryptoKey(key);
  }

  public override async onSign(algorithm: types.Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const cryptoAlg = ShaCrypto.getAlgorithmName(key.algorithm.hash);
    const hmac = crypto.createHmac(cryptoAlg, getCryptoKey(key).data)
      .update(Buffer.from(data)).digest();

    return new Uint8Array(hmac).buffer;
  }

  public override async onVerify(algorithm: types.Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const cryptoAlg = ShaCrypto.getAlgorithmName(key.algorithm.hash);
    const hmac = crypto.createHmac(cryptoAlg, getCryptoKey(key).data)
      .update(Buffer.from(data)).digest();

    return hmac.compare(Buffer.from(signature)) === 0;
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.HmacImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    let key: HmacCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: HmacCryptoKey });
        break;
      case "raw":
        key = new HmacCryptoKey();
        key.data = Buffer.from(keyData as ArrayBuffer);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = {
      hash: { name: (algorithm.hash as types.Algorithm).name },
      name: this.name,
      length: key.data.length << 3,
    };
    key.extractable = extractable;
    key.usages = keyUsages;

    return setCryptoKey(key);
  }

  public async onExportKey(format: types.KeyFormat, key: HmacCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return jsonSchema.JsonSerializer.toJSON(getCryptoKey(key));
      case "raw":
        return new Uint8Array(getCryptoKey(key).data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

}
