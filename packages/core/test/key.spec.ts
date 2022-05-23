import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";

context("CryptoKey", () => {

  context("isKeyType", () => {
    it("correct key type", () => {
      assert.equal(core.CryptoKey.isKeyType("secret"), true);
    });
    it("incorrect key type", () => {
      assert.equal(core.CryptoKey.isKeyType("Secret"), false);
    });
  });

});
