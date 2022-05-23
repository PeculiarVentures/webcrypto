import * as types from "@peculiar/webcrypto-types";
import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";

class DesTestProvider extends core.DesProvider {
  public keySizeBits = 64;
  public ivSize = 8;
  public name = "DES-TEST";

  public onGenerateKey(algorithm: import("../src/des").DesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    throw new Error("Method not implemented.");
  }
  public onExportKey(format: types.KeyFormat, key: core.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: import("../src/des").DesImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    throw new Error("Method not implemented.");
  }
  public onEncrypt(algorithm: import("../src/des").DesParams, key: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onDecrypt(algorithm: import("../src/des").DesParams, key: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
}

context("DES", () => {

  const provider = new DesTestProvider();

  context("checkAlgorithmParams", () => {

    it("error if `iv` is not present", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
        } as any);
      }, Error);
    });

    it("error if `iv` has wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
          iv: "wrong type",
        } as any);
      }, TypeError);
    });

    it("error if `iv` has wrong length", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({
          iv: new ArrayBuffer(9),
        } as any);
      }, TypeError);
    });

    it("correct `iv` length", () => {
      provider.checkAlgorithmParams({
        iv: new Uint8Array(8),
      } as any);
    });

  });

  context("checkGenerateKeyParams", () => {

    it("error if `length` is not present", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({} as any);
      }, Error);
    });

    it("error if `length` has wrong type", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({ length: "8" } as any);
      }, TypeError);
    });

    it("error if `length` has wrong value", () => {
      assert.throws(() => {
        provider.checkGenerateKeyParams({ length: 8 } as any);
      }, core.OperationError);
    });

    it("correct value", () => {
      provider.checkGenerateKeyParams({ length: 64 } as any);
    });

  });

});
