import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { ShaCrypto } from "../sha/crypto";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaSsaProvider extends core.RsaSsaProvider {

  public async onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: types.KeyFormat, key: RsaCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<RsaCryptoKey> {
    return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onSign(algorithm: types.Algorithm, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const rsa = new asmCrypto.RSA_PKCS1_v1_5(key.data, ShaCrypto.getDigest(key.algorithm.hash.name));
    const result = rsa.sign(pvtsutils.BufferSourceConverter.toUint8Array(data));
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onVerify(algorithm: types.Algorithm, key: RsaCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const rsa = new asmCrypto.RSA_PKCS1_v1_5(key.data, ShaCrypto.getDigest(key.algorithm.hash.name));
    try {
      rsa.verify(pvtsutils.BufferSourceConverter.toUint8Array(signature), pvtsutils.BufferSourceConverter.toUint8Array(data));
    } catch {
      return false;
    }
    return true;
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is RsaCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

}
