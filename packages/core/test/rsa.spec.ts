import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";

context("RSA", () => {

  context("RSASSA-PKCS1-v1_5", () => {

    const provider = Reflect.construct(core.RsaSsaProvider, []) as core.RsaSsaProvider;

    context("checkGenerateKeyParams", () => {

      it("error if `hash` is missing", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }, Error);
      });

      it("error if `hash` is wrong", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-WRONG" },
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }, Error);
      });

      it("error if `publicExponent` is missing", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            modulusLength: 2048,
          } as any);
        }, Error);
      });

      it("error if `publicExponent` is wrong of type", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: [1, 0, 1],
            modulusLength: 2048,
          } as any);
        }, TypeError);
      });

      it("error if `publicExponent` is value", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: new Uint8Array([1, 1, 0]),
            modulusLength: 2048,
          } as any);
        }, TypeError);
      });

      it("error if `modulusLength` is missing", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({
            hash: { name: "SHA-256" },
            publicExponent: new Uint8Array([1, 0, 1]),
          } as any);
        }, Error);
      });

      it("error if `modulusLength` is wrong value", () => {
        it("not multiple of 8 bits", () => {
          assert.throws(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 12345,
            } as any);
          }, TypeError);
        });
        it("less than 256", () => {
          assert.throws(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 256 - 8,
            } as any);
          }, TypeError);
        });
        it("more than 16384", () => {
          assert.throws(() => {
            provider.checkGenerateKeyParams({
              hash: { name: "SHA-256" },
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 16384 + 8,
            } as any);
          }, TypeError);
        });
      });

      it("correct value", () => {
        provider.checkGenerateKeyParams({
          hash: { name: "SHA-256" },
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 4096,
        } as any);
      });

    });

    context("checkImportParams", () => {

      it("error if `hash` is missing", () => {
        assert.throws(() => {
          provider.checkImportParams({
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }, Error);
      });

      it("error if `hash` is wrong", () => {
        assert.throws(() => {
          provider.checkImportParams({
            hash: { name: "SHA-WRONG" },
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          } as any);
        }, Error);
      });

    });

  });

  context("RSA-OAEP", () => {

    const provider = Reflect.construct(core.RsaOaepProvider, []) as core.RsaOaepProvider;

    context("checkAlgorithmParams", () => {

      it("error if `label` is wrong type", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({ label: "WRONG" } as any);
        }, TypeError);
      });

      it("correct `label`", () => {
        provider.checkAlgorithmParams({ label: new Uint8Array(4) } as any);
      });

    });

  });

  context("RSA-PSS", () => {

    const provider = Reflect.construct(core.RsaPssProvider, []) as core.RsaPssProvider;

    context("checkAlgorithmParams", () => {

      it("error if `saltLength` is missing", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if `saltLength` is not of type Number", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({ saltLength: "123" } as any);
        }, TypeError);
      });

      it("error if `saltLength` is less than 0", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({ saltLength: -1 } as any);
        }, RangeError);
      });

      it("correct `saltLength`", () => {
        provider.checkAlgorithmParams({ saltLength: 8 } as any);
      });

    });

  });

});
