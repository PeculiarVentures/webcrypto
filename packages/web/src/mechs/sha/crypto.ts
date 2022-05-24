import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as asmCrypto from "asmcrypto.js";
import * as pvtsutils from "pvtsutils";

export class ShaCrypto {

  public static getDigest(name: string) {
    switch (name) {
      case "SHA-1":
        return new asmCrypto.Sha1();
      case "SHA-256":
        return new asmCrypto.Sha256();
      case "SHA-512":
        return new asmCrypto.Sha512();
      default:
        throw new core.AlgorithmError("keyAlgorithm.hash: Is not recognized");
    }
  }

  public static async digest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    const mech = this.getDigest(algorithm.name);

    const result = mech
      .process(pvtsutils.BufferSourceConverter.toUint8Array(data))
      .finish().result;
    if (!result) {
      throw new core.OperationError("SHA digest result is empty");
    }
    return pvtsutils.BufferSourceConverter.toArrayBuffer(result);
  }
}
