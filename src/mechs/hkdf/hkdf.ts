import * as core from "webcrypto-core";
import { HmacCryptoKey } from "../hmac/key";
import { HkdfCryptoKey } from "./key";
import { BufferSourceConverter, CryptoKey } from "webcrypto-core";
import crypto from "crypto";

export class HkdfProvider extends core.HkdfProvider {

  private normalizeHash(hash: HashAlgorithmIdentifier): Algorithm {
    if (typeof hash === "string") {
      hash = {name: hash};
    }

    this.checkHashAlgorithm(hash, this.hashAlgorithms);
    return hash;
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format.toLowerCase() !== "raw") {
        throw new core.OperationError("Operation not supported");
    }

    const key: HkdfCryptoKey = new HkdfCryptoKey();
    key.data = Buffer.from(keyData);
    key.algorithm = { name: this.name };
    key.extractable = extractable;
    key.usages = keyUsages;
    return key;
  }

  public async onExportKey(format: KeyFormat, key: HmacCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'raw'");
    }
  }

  public async onDeriveBits(params: HkdfParams, baseKey: HkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    const hash = this.normalizeHash(params.hash).name.replace("-", "");
    const hashLength = crypto.createHash(hash).digest().length;

    const byteLength = length / 8;
    const info = BufferSourceConverter.toUint8Array(params.info);

    const PRK = crypto.createHmac(hash, BufferSourceConverter.toUint8Array(params.salt))
        .update(BufferSourceConverter.toUint8Array(baseKey.data))
        .digest();

    let blocks = [Buffer.alloc(0)];
    const blockCount = Math.ceil(byteLength / hashLength) + 1; // Includes empty buffer
    for (let i=1; i<blockCount; ++i) {
      blocks.push(
          crypto.createHmac(hash, PRK)
            .update(Buffer.concat([blocks[i - 1], info, Buffer.from([i])]))
            .digest()
      );
    }

    return Buffer.concat(blocks).slice(0, byteLength);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HkdfCryptoKey)) {
      throw new TypeError("key: Is not HKDF CryptoKey");
    }
  }

}
