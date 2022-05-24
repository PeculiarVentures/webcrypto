import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";
import { ShaCrypto } from "../sha/crypto";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: types.KeyFormat, key: RsaCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<RsaCryptoKey> {
    return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: types.RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cipher(algorithm, key, data);
  }

  public async onDecrypt(algorithm: types.RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cipher(algorithm, key, data);
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage: types.KeyUsage): asserts key is RsaCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

  private cipher(algorithm: types.RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer) {
    const digest = ShaCrypto.getDigest(key.algorithm.hash.name);
    let label: Uint8Array | undefined;
    if (algorithm.label) {
      label = pvtsutils.BufferSourceConverter.toUint8Array(algorithm.label);
    }
    const cipher = new asmCrypto.RSA_OAEP(key.data, digest, label);
    let res: Uint8Array;
    const u8Data = pvtsutils.BufferSourceConverter.toUint8Array(data);
    if (key.type === "public") {
      res = cipher.encrypt(u8Data);
    } else {
      res = cipher.decrypt(u8Data);
    }
    return pvtsutils.BufferSourceConverter.toArrayBuffer(res);
  }

}
