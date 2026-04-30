import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import {
  assertBufferSource, toArrayBuffer, toUint8Array,
} from "@peculiar/utils";
import * as core from "webcrypto-core";
import { setCryptoKey, getCryptoKey } from "../storage";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {
  public async onDeriveBits(algorithm: Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const salt = toUint8Array(algorithm.salt);
      const hash = (algorithm.hash as Algorithm).name.replace("-", "");
      crypto.pbkdf2(getCryptoKey(baseKey).data, Buffer.from(salt), algorithm.iterations, length >> 3, hash, (err, derivedBits) => {
        if (err) {
          reject(err);
        } else {
          resolve(toArrayBuffer(derivedBits));
        }
      });
    });
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format === "raw") {
      assertBufferSource(keyData);
      const key = new PbkdfCryptoKey();
      key.data = Buffer.from(toUint8Array(keyData));
      key.algorithm = { name: this.name };
      key.extractable = false;
      key.usages = keyUsages;
      return setCryptoKey(key);
    }
    throw new core.OperationError("format: Must be 'raw'");
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof PbkdfCryptoKey)) {
      throw new TypeError("key: Is not PBKDF CryptoKey");
    }
  }
}
