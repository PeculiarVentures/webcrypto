import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import * as pvtsutils from "pvtsutils";
import { setCryptoKey, getCryptoKey } from "../storage";
import { HkdfCryptoKey } from "./key";

export class HkdfProvider extends core.HkdfProvider {

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer, algorithm: types.HmacImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    if (format.toLowerCase() !== "raw") {
      throw new core.OperationError("Operation not supported");
    }

    const key: HkdfCryptoKey = new HkdfCryptoKey();
    key.data = Buffer.from(keyData);
    key.algorithm = { name: this.name };
    key.extractable = extractable;
    key.usages = keyUsages;
    return setCryptoKey(key);
  }

  public async onDeriveBits(params: types.HkdfParams, baseKey: HkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    const hash = (params.hash as types.Algorithm).name.replace("-", "");
    const hashLength = crypto.createHash(hash).digest().length;

    const byteLength = length / 8;
    const info = pvtsutils.BufferSourceConverter.toUint8Array(params.info);

    const PRK = crypto.createHmac(hash, pvtsutils.BufferSourceConverter.toUint8Array(params.salt))
      .update(pvtsutils.BufferSourceConverter.toUint8Array(getCryptoKey(baseKey).data))
      .digest();

    const blocks = [Buffer.alloc(0)];
    const blockCount = Math.ceil(byteLength / hashLength) + 1; // Includes empty buffer
    for (let i = 1; i < blockCount; ++i) {
      blocks.push(
        crypto.createHmac(hash, PRK)
          .update(Buffer.concat([blocks[i - 1], info, Buffer.from([i])]))
          .digest(),
      );
    }

    return Buffer.concat(blocks).slice(0, byteLength);
  }

  public override checkCryptoKey(key: core.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof HkdfCryptoKey)) {
      throw new TypeError("key: Is not HKDF CryptoKey");
    }
  }

}
