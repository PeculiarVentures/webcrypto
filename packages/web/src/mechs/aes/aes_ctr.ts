import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import * as asmCrypto from "asmcrypto.js";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCtrProvider extends core.AesCtrProvider {

  public async onEncrypt(algorithm: types.AesCtrParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const result = new asmCrypto.AES_CTR(key.raw, pvtsutils.BufferSourceConverter.toUint8Array(algorithm.counter))
      .encrypt(pvtsutils.BufferSourceConverter.toUint8Array(data));
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onDecrypt(algorithm: types.AesCtrParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const result = new asmCrypto.AES_CTR(key.raw, pvtsutils.BufferSourceConverter.toUint8Array(algorithm.counter))
      .decrypt(pvtsutils.BufferSourceConverter.toUint8Array(data));
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    return AesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: types.KeyFormat, key: AesCryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return AesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }
}
