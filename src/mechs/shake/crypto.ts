import crypto from "crypto";

export class ShakeCrypto {

  public static digest(algorithm: Algorithm, data: ArrayBuffer) {
    const hash = crypto.createHash(algorithm.name.toLowerCase())
      .update(Buffer.from(data)).digest();
    return new Uint8Array(hash).buffer;
  }

}
