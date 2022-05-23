import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";
import { BufferSource } from "pvtsutils";

export interface DesKeyAlgorithm extends types.KeyAlgorithm {
  length: number;
}

export interface DesParams extends types.Algorithm {
  iv: BufferSource;
}

export interface DesKeyGenParams extends types.Algorithm {
  length: number;
}

export interface DesDerivedKeyParams extends types.Algorithm {
  length: number;
}

export interface DesImportParams extends types.Algorithm { }

export abstract class DesProvider extends ProviderCrypto {

  public usages: types.KeyUsages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  public abstract keySizeBits: number;
  public abstract ivSize: number;

  public override checkAlgorithmParams(algorithm: types.AesCbcParams) {
    if (this.ivSize) {
      this.checkRequiredProperty(algorithm, "iv");
      if (!(algorithm.iv instanceof ArrayBuffer || ArrayBuffer.isView(algorithm.iv))) {
        throw new TypeError("iv: Is not of type '(ArrayBuffer or ArrayBufferView)'");
      }
      if (algorithm.iv.byteLength !== this.ivSize) {
        throw new TypeError(`iv: Must have length ${this.ivSize} bytes`);
      }
    }
  }

  public override checkGenerateKeyParams(algorithm: DesKeyGenParams) {
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    if (algorithm.length !== this.keySizeBits) {
      throw new OperationError(`algorithm.length: Must be ${this.keySizeBits}`);
    }
  }

  public override checkDerivedKeyParams(algorithm: DesDerivedKeyParams) {
    this.checkGenerateKeyParams(algorithm);
  }

  public abstract override onGenerateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: types.KeyFormat, key: CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: DesImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onEncrypt(algorithm: DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
