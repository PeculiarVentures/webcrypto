import crypto from "crypto";

export class ShaCrypto {

  public static digest(algorithm: Algorithm, data: ArrayBuffer) {
    const hash = crypto.createHash(algorithm.name.replace("-", ""))
      .update(Buffer.from(data)).digest();
    return new Uint8Array(hash).buffer;
  }

}
