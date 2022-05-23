import * as assert from "assert";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

context("Crypto", () => {

  it("Crypto matches to globalThis.Crypto", () => {
    class MyCrypto extends core.Crypto {
      public subtle = new core.SubtleCrypto();
      public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        throw new Error("Method not implemented.");
      }

    }

    let crypto: types.Crypto;
    crypto = new MyCrypto();
    assert.ok(crypto);
  });

});
