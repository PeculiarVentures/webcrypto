import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesKwProvider extends core.AesKwProvider {
  public override async onEncrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public override async onDecrypt(algorithm: types.Algorithm, key: types.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    throw new Error("Method not implemented.");
  }
  public async onExportKey(format: types.KeyFormat, key: types.CryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<AesCryptoKey> {
    throw new Error("Method not implemented.");
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }
}
