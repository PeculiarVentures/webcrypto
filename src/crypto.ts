import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import * as core from "webcrypto-core";
import { SubtleCrypto } from "./subtle";

interface GenerateKeyPair {
  generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams, extractable: boolean, keyUsages: ReadonlyArray<KeyUsage>): Promise<CryptoKeyPair>;
}

export class Crypto extends core.Crypto {
  // Adds the DOM overloads, so callers can pass EcdsaParams, AesGcmParams, etc. as object
  // literals; core's SubtleCrypto only accepts AlgorithmIdentifier there. GenerateKeyPair
  // comes first so readonly usages (`as const`) still return a CryptoKeyPair.
  public subtle: GenerateKeyPair & SubtleCrypto & globalThis.SubtleCrypto = new SubtleCrypto();

  public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    if (!ArrayBuffer.isView(array)) {
      throw new TypeError("Failed to execute 'getRandomValues' on 'Crypto': parameter 1 is not of type 'ArrayBufferView'");
    }
    const buffer = Buffer.from(array.buffer, array.byteOffset, array.byteLength);
    crypto.randomFillSync(buffer);
    return array;
  }
}
