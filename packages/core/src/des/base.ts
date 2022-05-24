import * as types from "@peculiar/webcrypto-types";
import { OperationError } from "../errors";
import { CryptoKey } from "../crypto_key";
import { ProviderCrypto } from "../provider";

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

  public override checkGenerateKeyParams(algorithm: types.DesKeyGenParams) {
    // length
    this.checkRequiredProperty(algorithm, "length");
    if (typeof algorithm.length !== "number") {
      throw new TypeError("length: Is not of type Number");
    }
    if (algorithm.length !== this.keySizeBits) {
      throw new OperationError(`algorithm.length: Must be ${this.keySizeBits}`);
    }
  }

  public override checkDerivedKeyParams(algorithm: types.DesDerivedKeyParams) {
    this.checkGenerateKeyParams(algorithm);
  }

  public abstract override onGenerateKey(algorithm: types.DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onExportKey(format: types.KeyFormat, key: CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public abstract override onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.DesImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<CryptoKey>;
  public abstract override onEncrypt(algorithm: types.DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
  public abstract override onDecrypt(algorithm: types.DesParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;

}
