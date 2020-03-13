import crypto from "crypto";
import * as core from "webcrypto-core";
import { BufferSourceConverter, CryptoKey } from "webcrypto-core";
import { setCryptoKey, getCryptoKey } from "../storage";
import { HkdfCryptoKey } from "./key";

export class HkdfProvider extends core.HkdfProvider {

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
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

  public async onDeriveBits(params: HkdfParams, baseKey: HkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    const hash = (params.hash as Algorithm).name.replace("-", "");
    const hashLength = crypto.createHash(hash).digest().length;

    const byteLength = length / 8;
    const info = BufferSourceConverter.toUint8Array(params.info);

    const PRK = crypto.createHmac(hash, BufferSourceConverter.toUint8Array(params.salt))
        .update(BufferSourceConverter.toUint8Array(getCryptoKey(baseKey).data))
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

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof HkdfCryptoKey)) {
      throw new TypeError("key: Is not HKDF CryptoKey");
    }
  }

}
