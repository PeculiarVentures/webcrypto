import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<PbkdfCryptoKey> {
    return new PbkdfCryptoKey(
      algorithm,
      extractable,
      keyUsages,
      pvtsutils.BufferSourceConverter.toUint8Array(keyData as ArrayBuffer),
    );
  }

  public async onDeriveBits(algorithm: types.Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    let result: Uint8Array;
    const salt = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.salt);
    const password = baseKey.raw;
    switch ((algorithm.hash as types.Algorithm).name.toUpperCase()) {
      case "SHA-1":
        result = asmCrypto.Pbkdf2HmacSha1(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-256":
        result = asmCrypto.Pbkdf2HmacSha256(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-512":
        result = asmCrypto.Pbkdf2HmacSha512(password, salt, algorithm.iterations, length >> 3);
        break;
      default:
        throw new core.OperationError(`algorithm.hash: '${(algorithm.hash as types.Algorithm).name}' hash algorithm is not supported`);
    }
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is PbkdfCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof PbkdfCryptoKey)) {
      throw new TypeError("key: Is not PbkdfCryptoKey");
    }
  }

}
