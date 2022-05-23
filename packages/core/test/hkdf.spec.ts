import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";

context("HKDF", () => {

  const provider = Reflect.construct(core.HkdfProvider, []) as core.HkdfProvider;

  context("checkAlgorithmParams", () => {

    it("error if `hash` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ salt: new Uint8Array(4), info: new Uint8Array(4) } as any);
      }, Error);
    });

    it("error if `hash` is wrong", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "WRONG" }, salt: new Uint8Array(4), info: new Uint8Array(4) } as any);
      }, core.OperationError);
    });

    it("error if `salt` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, info: new Uint8Array(4) } as any);
      }, Error);
    });

    it("error if `salt` wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: "wrong", info: new Uint8Array(4) } as any);
      }, TypeError);
    });

    it("error if `info` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4) } as any);
      }, Error);
    });

    it("error if `info` wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, info: "wrong", salt: new Uint8Array(4) } as any);
      }, TypeError);
    });

    it("correct value", () => {
      provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4), info: new Uint8Array(4) } as any);
    });

  });

  context("checkImportKey", () => {

    it("throw error if extractable is true", () => {
      assert.throws(() => {
        provider.checkImportKey("raw", new ArrayBuffer(0), { name: "HKDF" }, true, ["deriveBits"]);
      }, SyntaxError);
    });

    it("correct extractable value", () => {
      provider.checkImportKey("raw", new ArrayBuffer(0), { name: "HKDF" }, false, ["deriveBits"]);
    });

  });

});
