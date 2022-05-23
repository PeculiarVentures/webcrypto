import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import * as pvtsutils from "pvtsutils";
import { setCryptoKey, getCryptoKey } from "../storage";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {

  public async onDeriveBits(algorithm: types.Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const salt = pvtsutils.BufferSourceConverter.toArrayBuffer(algorithm.salt);
      const hash = (algorithm.hash as types.Algorithm).name.replace("-", "");
      crypto.pbkdf2(getCryptoKey(baseKey).data, Buffer.from(salt), algorithm.iterations, length >> 3, hash, (err, derivedBits) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(derivedBits).buffer);
        }
      });
    });
  }

  public async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    if (format === "raw") {
      const key = new PbkdfCryptoKey();
      key.data = Buffer.from(keyData as ArrayBuffer);
      key.algorithm = { name: this.name };
      key.extractable = false;
      key.usages = keyUsages;
      return setCryptoKey(key);
    }
    throw new core.OperationError("format: Must be 'raw'");
  }

  public override checkCryptoKey(key: types.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof PbkdfCryptoKey)) {
      throw new TypeError("key: Is not PBKDF CryptoKey");
    }
  }

}
