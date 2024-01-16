import { Buffer } from "buffer";
import crypto from "crypto";

export class ShaCrypto {

  /**
   * Returns size of the hash algorithm in bits
   * @param algorithm Hash algorithm
   * @throws Throws Error if an unrecognized name
   */
  public static size(algorithm: Algorithm) {
    switch (algorithm.name.toUpperCase()) {
      case "SHA-1":
        return 160;
      case "SHA-256":
      case "SHA3-256":
        return 256;
      case "SHA-384":
      case "SHA3-384":
        return 384;
      case "SHA-512":
      case "SHA3-512":
        return 512;
      default:
        throw new Error("Unrecognized name");
    }
  }

  /**
   * Returns NodeJS Crypto algorithm name from WebCrypto algorithm
   * @param algorithm WebCRypto algorithm
   * @throws Throws Error if an unrecognized name
   */
  public static getAlgorithmName(algorithm: Algorithm): string {
    switch (algorithm.name.toUpperCase()) {
      case "SHA-1":
        return "sha1";
      case "SHA-256":
        return "sha256";
      case "SHA-384":
        return "sha384";
      case "SHA-512":
        return "sha512";
      case "SHA3-256":
        return "sha3-256";
      case "SHA3-384":
        return "sha3-384";
      case "SHA3-512":
        return "sha3-512";
      default:
        throw new Error("Unrecognized name");
    }
  }

  public static digest(algorithm: Algorithm, data: ArrayBuffer) {
    const hashAlg = this.getAlgorithmName(algorithm);
    const hash = crypto.createHash(hashAlg)
      .update(Buffer.from(data)).digest();
    return new Uint8Array(hash).buffer;
  }

}
