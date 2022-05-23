import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";

context("HMAC", () => {

  const provider = Reflect.construct(core.Pbkdf2Provider, []) as core.Pbkdf2Provider;

  context("checkAlgorithmParams", () => {

    it("error if `hash` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ salt: new Uint8Array(4), iterations: 1000 } as any);
      }, Error);
    });

    it("error if `hash` is wrong", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "WRONG" }, salt: new Uint8Array(4), iterations: 1000 } as any);
      }, core.OperationError);
    });

    it("error if `salt` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, iterations: 1000 } as any);
      }, Error);
    });

    it("error if `salt` wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: "wrong", iterations: 1000 } as any);
      }, TypeError);
    });

    it("error if `iterations` is missing", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4) } as any);
      }, Error);
    });

    it("error if `iterations` wrong type", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4), iterations: "123" } as any);
      }, TypeError);
    });

    it("error if `iterations` less than 1", () => {
      assert.throws(() => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4), iterations: 0 } as any);
      }, TypeError);
    });

    it("correct value", () => {
      provider.checkAlgorithmParams({ hash: { name: "SHA-256" }, salt: new Uint8Array(4), iterations: 1000 } as any);
    });

  });

  context("checkImportKey", () => {

    it("throw error if extractable is true", () => {
      assert.throws(() => {
        provider.checkImportKey("raw", new ArrayBuffer(0), { name: "PBKDF2" }, true, ["deriveBits"]);
      }, SyntaxError);
    });

    it("correct extractable value", () => {
      provider.checkImportKey("raw", new ArrayBuffer(0), { name: "PBKDF2" }, false, ["deriveBits"]);
    });

  });

});
