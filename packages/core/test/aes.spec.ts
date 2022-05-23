import * as assert from "assert";
import * as core from "@peculiar/webcrypto-core";

// tslint:disable:max-classes-per-file

context("AES", () => {

  context("AES-CBC", () => {

    const provider = Reflect.construct(core.AesCbcProvider, []) as core.AesCbcProvider;

    context("checkGenerateKeyParams", () => {

      it("error if `length` is not present", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ name: "AES-CBC" } as any);
        }, Error);
      });

      it("error if `length` has wrong type", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ name: "AES-CBC", length: "s" } as any);
        }, TypeError);
      });

      it("error if `length` has wrong value", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ name: "AES-CBC", length: 1 } as any);
        }, TypeError);
      });

      [128, 192, 256].forEach((length) => {
        it(`correct length:${length}`, () => {
          provider.checkGenerateKeyParams({ name: "AES-CBC", length } as any);
        });
      });

    });

  });

  context("AES-CBC", () => {

    const provider = Reflect.construct(core.AesCbcProvider, []) as core.AesCbcProvider;

    context("checkAlgorithmParams", () => {

      it("error if parameter `iv` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: "wrong type",
          } as any);
        }, TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new Uint8Array(20),
          } as any);
        }, TypeError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({
          iv: new Uint8Array(16),
        } as any);
      });

    });

  });

  context("AES-CMAC", () => {

    const provider = Reflect.construct(core.AesCmacProvider, []) as core.AesCmacProvider;

    context("checkAlgorithmParams", () => {

      it("error if parameter `length` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `length` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: "128",
          } as any);
        }, TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: 0,
          } as any);
        }, core.OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({
          length: 1,
        } as any);
      });

    });

  });

  context("AES-CTR", () => {

    const provider = Reflect.construct(core.AesCtrProvider, []) as core.AesCtrProvider;

    context("checkAlgorithmParams", () => {

      it("error if parameter `counter` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            length: 1,
          } as any);
        }, Error);
      });

      it("error if parameter `counter` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: "wrong type",
            length: 1,
          } as any);
        }, TypeError);
      });

      it("error if parameter `counter` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new ArrayBuffer(10),
            length: 1,
          } as any);
        }, TypeError);
      });

      it("counter is ArrayBuffer", () => {
        provider.checkAlgorithmParams({
          counter: new ArrayBuffer(16),
          length: 1,
        } as any);
      });

      it("counter is ArrayBufferView", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });

      it("error if parameter `length` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
          } as any);
        }, Error);
      });

      it("error if parameter `length` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: "1",
          } as any);
        }, TypeError);
      });

      it("error if parameter `length` less than 1", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            counter: new Uint8Array(16),
            length: 0,
          } as any);
        }, core.OperationError);
      });

      it("correct parameter `length`", () => {
        provider.checkAlgorithmParams({
          counter: new Uint8Array(16),
          length: 1,
        } as any);
      });

    });

  });

  context("AES-GCM", () => {

    const provider = Reflect.construct(core.AesGcmProvider, []) as core.AesGcmProvider;

    context("checkAlgorithmParams", () => {

      it("error if parameter `iv` is not present", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if parameter `iv` has wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: "wrong type",
          } as any);
        }, TypeError);
      });

      it("error if parameter `iv` has wrong length", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new Uint8Array(0),
          } as any);
        }, core.OperationError);
      });

      it("correct parameter `iv`", () => {
        provider.checkAlgorithmParams({
          iv: new ArrayBuffer(1),
        } as any);
      });

      it("error if parameter `tagLength` has wrong value", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength: 33,
          } as any);
        }, core.OperationError);
      });

      [32, 64, 96, 104, 112, 120, 128].forEach((tagLength) => {
        it(`correct tagLength: ${tagLength}`, () => {
          provider.checkAlgorithmParams({
            iv: new ArrayBuffer(1),
            tagLength,
          } as any);
        });
      });

    });

  });

});
