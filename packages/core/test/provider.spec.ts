import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";

class TestProvider extends core.ProviderCrypto {
  public name = "CUSTOM-ALG";
  public usages: types.KeyUsage[] = ["sign"];
}

class TestAsymmetricProvider extends core.ProviderCrypto {
  public name = "CUSTOM-ALG";
  public usages: types.ProviderKeyPairUsage = {
    privateKey: ["sign"],
    publicKey: ["verify"],
  };
}

context("ProviderCrypto", () => {

  const crypto = new TestProvider();

  context("checkGenerateKey", () => {

    it("error if `keyUsages` argument is empty list", () => {
      assert.throws(() => {
        crypto.checkGenerateKey({ name: "CUSTOM-ALG" }, true, []);
      }, TypeError);
    });

    it("check usages for symmetric key", () => {
      const aProv = new TestAsymmetricProvider();
      aProv.checkGenerateKey({ name: "CUSTOM-ALG" }, true, ["sign", "verify"]);
    });

  });

  context("digest", () => {

    it("correct data", async () => {
      await assert.rejects(
        crypto.digest({ name: "custom-alg" }, new ArrayBuffer(0)),
        core.UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.digest({ name: "wrong" }, new ArrayBuffer(0)),
      );
    });

  });

  context("generateKey", () => {

    it("correct data", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "custom-alg" }, true, ["sign"]),
        core.UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "wrong" }, false, ["sign"]),
      );
    });

    it("wrong key usages", async () => {
      await assert.rejects(
        crypto.generateKey({ name: "custom-alg" }, false, ["verify"]),
      );
    });

  });

  context("sign", () => {

    const correctKey = core.CryptoKey.create(
      { name: "custom-alg" },
      "secret",
      false,
      ["sign"],
    );

    it("correct data", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          correctKey,
          new ArrayBuffer(0),
        ),
        core.UnsupportedOperationError,
      );
    });

    it("wrong name of algorithm", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "wrong" },
          correctKey,
          new ArrayBuffer(0),
        ),
      );
    });

    it("wrong key type", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          {} as core.CryptoKey,
          new ArrayBuffer(0),
        ),
        TypeError,
      );
    });

    it("wrong key algorithm", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          core.CryptoKey.create(
            { name: "wrong" },
            "secret",
            true,
            ["sign", "decrypt"],
          ),
          new ArrayBuffer(0),
        ),
        core.AlgorithmError,
      );
    });

    it("wrong key usage", async () => {
      await assert.rejects(
        crypto.sign(
          { name: "custom-alg" },
          core.CryptoKey.create(
            { name: "custom-alg" },
            "secret",
            true,
            ["verify"],
          ),
          new ArrayBuffer(0),
        ),
        core.CryptoError,
      );
    });

  });

  context("checkDeriveBits", () => {

    it("error if length is not multiple 8", () => {
      const algorithm: types.Algorithm = { name: "custom-alg" };
      const key = core.CryptoKey.create(algorithm, "secret", false, ["deriveBits"]);
      assert.throws(() => {
        crypto.checkDeriveBits(algorithm, key, 7);
      }, core.OperationError);
    });

  });

  context("checkKeyFormat", () => {

    it("error if wrong value", () => {
      assert.throws(() => {
        crypto.checkKeyFormat("wrong");
      }, TypeError);
    });

  });

});
