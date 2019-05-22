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
        return 256;
      case "SHA-384":
        return 384;
      case "SHA-512":
        return 512;
      default:
        throw new Error("Unrecognized name");
    }
  }

  public static digest(algorithm: Algorithm, data: ArrayBuffer) {
    const hash = crypto.createHash(algorithm.name.replace("-", ""))
      .update(Buffer.from(data)).digest();
    return new Uint8Array(hash).buffer;
  }

}
