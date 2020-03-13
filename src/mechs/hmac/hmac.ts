import crypto from "crypto";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  public async onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const length = algorithm.length || this.getDefaultLength((algorithm.hash as Algorithm).name);
    const key = new HmacCryptoKey();
    key.algorithm = {
      ...algorithm as any,
      name: this.name,
    };
    key.extractable = extractable;
    key.usages = keyUsages;
    key.data = crypto.randomBytes(length >> 3);

    return key;
  }

  public async onSign(algorithm: Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const hash = key.algorithm.hash.name.replace("-", "");
    const hmac = crypto.createHmac(hash, key.data)
      .update(Buffer.from(data)).digest();

    return new Uint8Array(hmac).buffer;
  }

  public async onVerify(algorithm: Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const hash = key.algorithm.hash.name.replace("-", "");
    const hmac = crypto.createHmac(hash, key.data)
      .update(Buffer.from(data)).digest();

    return hmac.compare(Buffer.from(signature)) === 0;
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    let key: HmacCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = JsonParser.fromJSON(keyData, { targetSchema: HmacCryptoKey });
        break;
      case "raw":
        key = new HmacCryptoKey();
        key.data = Buffer.from(keyData as ArrayBuffer);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = {
      hash: { name: (algorithm.hash as Algorithm).name },
      name: this.name,
      length: key.data.length << 3,
    };
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  public async onExportKey(format: KeyFormat, key: HmacCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

}
