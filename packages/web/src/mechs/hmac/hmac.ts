import * as jsonSchema from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { nativeCrypto } from "../../native";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  public async onGenerateKey(algorithm: types.HmacKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<HmacCryptoKey> {
    const length = algorithm.length || this.getDefaultLength((algorithm.hash as types.Algorithm).name);

    // get random bytes for key
    const raw = nativeCrypto.getRandomValues(new Uint8Array(length >> 3));

    const key = new HmacCryptoKey(algorithm, extractable, keyUsages, raw);

    return key;
  }

  public override async onSign(algorithm: types.Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    let fn: typeof asmCrypto.HmacSha1 | typeof asmCrypto.HmacSha256 | typeof asmCrypto.HmacSha512;
    switch (key.algorithm.hash.name.toUpperCase()) {
      case "SHA-1":
        fn = asmCrypto.HmacSha1;
        break;
      case "SHA-256":
        fn = asmCrypto.HmacSha256;
        break;
      case "SHA-512":
        fn = asmCrypto.HmacSha512;
        break;
      default:
        throw new core.OperationError("key.algorithm.hash: Is not recognized");
    }

    const result = new fn(key.data)
      .process(pvtsutils.BufferSourceConverter.toUint8Array(data))
      .finish().result;
    if (!result) {
      throw new core.OperationError("HMAC signing result is empty");
    }

    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public override async onVerify(algorithm: types.Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const signature2 = await this.onSign(algorithm, key, data);
    return pvtsutils.Convert.ToHex(signature2) === pvtsutils.Convert.ToHex(signature);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.HmacImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<HmacCryptoKey> {
    let key: HmacCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = jsonSchema.JsonParser.fromJSON(keyData, { targetSchema: HmacCryptoKey });
        break;
      case "raw":
        if (!pvtsutils.BufferSourceConverter.isBufferSource(keyData)) {
          throw new TypeError("keyData: Is not ArrayBuffer or ArrayBufferView");
        }
        key = new HmacCryptoKey(algorithm, extractable, keyUsages, pvtsutils.BufferSourceConverter.toUint8Array(keyData));
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

    return key;
  }

  public async onExportKey(format: types.KeyFormat, key: HmacCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = jsonSchema.JsonSerializer.toJSON(key) as types.JsonWebKey;
        return jwk;
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

}
