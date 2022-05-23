import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { Convert } from "pvtsutils";

// tslint:disable:max-classes-per-file

context("EC", () => {

  context("EcUtils", () => {
    context("public point", () => {
      it("encode/decode point without padding", () => {
        const point = {
          x: new Uint8Array([1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4]),
          y: new Uint8Array([5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8]),
        };
        const encoded = core.EcUtils.encodePoint(point, 160);

        assert.strictEqual(Convert.ToHex(encoded), "0401010101010202020202030303030304040404040505050505060606060607070707070808080808");

        const decoded = core.EcUtils.decodePoint(encoded, 160);
        assert.strictEqual(Convert.ToHex(decoded.x), Convert.ToHex(point.x));
        assert.strictEqual(Convert.ToHex(decoded.y), Convert.ToHex(point.y));
      });
      it("decode uncompressed point ", () => {
        const uncompressedPoint = new Uint8Array(Convert.FromHex("0400010101010202020202030303030304040404040005050505060606060607070707070808080808"));
        const decoded = core.EcUtils.decodePoint(uncompressedPoint, 160);
        assert.strictEqual(Convert.ToHex(decoded.x), "0001010101020202020203030303030404040404");
        assert.strictEqual(Convert.ToHex(decoded.y), "0005050505060606060607070707070808080808");
      });
    });
    context("signature point", () => {
      it("encode/decode", () => {
        const encodedHex = "00f3e308185c2d6cb59ec216ba8ce31e0a27db431be250807e604cd858494eb9d1de066b0dc7964f64b31e2f8da7f00741b5ba7e3972fe476099d53f5c5a39905a1f009fc215304c42100a0eec7b9d0bbc5f59c838b604bcceb6ebffd4870c83e76d8eca92e689032caddc69aa87a833216163589f97ce6cb4d10c84b7d6a949e73ca1c5";
        const decoded = core.EcUtils.decodeSignature(Convert.FromHex(encodedHex), 521);
        assert.strictEqual(Convert.ToHex(decoded.r), "f3e308185c2d6cb59ec216ba8ce31e0a27db431be250807e604cd858494eb9d1de066b0dc7964f64b31e2f8da7f00741b5ba7e3972fe476099d53f5c5a39905a1f");
        assert.strictEqual(Convert.ToHex(decoded.s), "9fc215304c42100a0eec7b9d0bbc5f59c838b604bcceb6ebffd4870c83e76d8eca92e689032caddc69aa87a833216163589f97ce6cb4d10c84b7d6a949e73ca1c5");

        const encoded = core.EcUtils.encodeSignature(decoded, 521);
        assert.strictEqual(Convert.ToHex(encoded), encodedHex);
      });
    });
  });

  context("Base", () => {

    class EcTestProvider extends core.EllipticProvider {
      public namedCurves = ["P-1", "P-2"];
      public name = "ECC";
      public usages: types.ProviderKeyUsages = {
        privateKey: ["sign"],
        publicKey: ["verify"],
      };
      public onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
        throw new Error("Method not implemented.");
      }
      public onExportKey(format: types.KeyFormat, key: core.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
        throw new Error("Method not implemented.");
      }
      public onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
        throw new Error("Method not implemented.");
      }
    }

    const provider = new EcTestProvider();

    context("checkGenerateKeyParams", () => {

      it("error if `namedCurve` is missing", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({} as any);
        }, Error);
      });

      it("error if `namedCurve` is not of type String", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ namedCurve: 123 } as any);
        }, TypeError);
      });

      it("error if `namedCurve` is not value from list", () => {
        assert.throws(() => {
          provider.checkGenerateKeyParams({ namedCurve: "P-256" } as any);
        }, core.OperationError);
      });

      it("correct `namedCurve`", () => {
        provider.checkGenerateKeyParams({ namedCurve: "P-2" } as any);
      });

    });

  });

  context("ECDH", () => {

    const provider = Reflect.construct(core.EcdhProvider, []) as core.EcdhProvider;

    context("", () => {

      context("checkAlgorithmParams", () => {

        it("error if `public` is missing", () => {
          assert.throws(() => {
            provider.checkAlgorithmParams({} as any);
          }, Error);
        });

        it("error if `public` is not instance of CryptoKey", () => {
          assert.throws(() => {
            const key = {};
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("error if `public` is not public CryptoKey", () => {
          assert.throws(() => {
            const key = new core.CryptoKey();
            key.type = "secret";
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("error if `public` is wrong CryptoKey alg", () => {
          assert.throws(() => {
            const key = new core.CryptoKey();
            key.type = "public";
            key.algorithm = { name: "ECDSA" };
            provider.checkAlgorithmParams({ public: key } as any);
          }, Error);
        });

        it("correct `public`", () => {
          const key = new core.CryptoKey();
          key.type = "public";
          key.algorithm = { name: "ECDH" };
          provider.checkAlgorithmParams({ public: key } as any);
        });

      });

    });

  });

  context("ECDSA", () => {

    const provider = Reflect.construct(core.EcdsaProvider, []) as core.EcdsaProvider;

    context("checkAlgorithmParams", () => {

      it("error if `hash` is missing", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({} as any);
        }, Error);
      });

      it("error if `hash` has wrong value", () => {
        assert.throws(() => {
          provider.checkAlgorithmParams({ hash: { name: "wrong" } } as any);
        }, core.OperationError);
      });

      it("correct `hash`", () => {
        provider.checkAlgorithmParams({ hash: { name: "SHA-1" } } as any);
      });

    });

  });

  context("ECDH-ES", () => {
    class TestEcdhEsProvider extends core.EcdhEsProvider {
      public async onDeriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: core.CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }
      public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair> {
        return null as any;
      }
      public async onExportKey(format: types.KeyFormat, key: core.CryptoKey, ...args: any[]): Promise<ArrayBuffer | types.JsonWebKey> {
        return null as any;
      }
      public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<core.CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEcdhEsProvider();

    context("generateKey", () => {
      ["X25519", "x448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({ name: "ECDH-ES", namedCurve } as types.EcKeyGenParams, false, ["deriveBits", "deriveKey"]);
          assert.strictEqual(keys, null);
        });
      });
    });

  });

  context("EdDSA", () => {
    class TestEdDsaProvider extends core.EdDsaProvider {
      public async onSign(algorithm: types.EcdsaParams, key: core.CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer> {
        return null as any;
      }
      public async onVerify(algorithm: types.EcdsaParams, key: core.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer, ...args: any[]): Promise<boolean> {
        return true;
      }
      public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair> {
        return null as any;
      }
      public onExportKey(format: types.KeyFormat, key: core.CryptoKey, ...args: any[]): Promise<ArrayBuffer | types.JsonWebKey> {
        return null as any;
      }
      public onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<core.CryptoKey> {
        return null as any;
      }
    }
    const provider = new TestEdDsaProvider();

    context("generateKey", () => {
      ["Ed25519", "ed448"].forEach((namedCurve) => {
        it(namedCurve, async () => {
          const keys = await provider.generateKey({ name: "EdDSA", namedCurve } as types.EcKeyGenParams, false, ["sign", "verify"]);
          assert.strictEqual(keys, null);
        });
      });
    });

  });

});
