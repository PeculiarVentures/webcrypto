import * as core from "@peculiar/webcrypto-core";
import { EcKeyGenParams, KeyUsage, CryptoKeyPair, KeyFormat, JsonWebKey, EcKeyImportParams, CryptoKey, EcdsaParams } from "@peculiar/webcrypto-types";
import { Crypto } from "../../crypto";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

/**
 * Converts buffer to number array
 * @param buffer ArrayBuffer or ArrayBufferView
 */
export function b2a(buffer: ArrayBuffer | ArrayBufferView) {
  const buf = new Uint8Array(buffer as ArrayBuffer);
  const res: number[] = [];
  for (let i = 0; i < buf.length; i++) {
    res.push(buf[i]);
  }
  return res;
}

export class EcdsaProvider extends core.EcdsaProvider {

  public override hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"];
  public override namedCurves = ["P-256", "P-384", "P-521", "K-256", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"];

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return EcCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<EcCryptoKey> {
    return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onSign(algorithm: EcdsaParams, key: EcCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    EcCrypto.checkLib();

    // get digests
    const crypto = new Crypto();
    let array;

    const hash = await crypto.subtle.digest(algorithm.hash, data);
    array = b2a(hash);
    const signature = await key.data.sign(array);
    const asnSignature = new core.asn1.EcDsaSignature();
    asnSignature.r = new Uint8Array(signature.r.toArray()).buffer;
    asnSignature.s = new Uint8Array(signature.s.toArray()).buffer;

    return asnSignature.toWebCryptoSignature();
  }

  public async onVerify(algorithm: EcdsaParams, key: EcCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    EcCrypto.checkLib();

    const crypto = new Crypto();

    const sig = {
      r: new Uint8Array(signature.slice(0, signature.byteLength / 2)),
      s: new Uint8Array(signature.slice(signature.byteLength / 2)),
    };

    // get digest
    const hashedData = await crypto.subtle.digest(algorithm.hash, data);
    const array = b2a(hashedData);

    return key.data.verify(array, sig);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is EcCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(key);
  }

}
