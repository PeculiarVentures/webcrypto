// Test allows to validate that WebCrypto API from @peculiar/webcrypto-types matches to DOM WebCrypto
// NOTE: This file should be in 'exclude' option of tsconfig.json file

/// <reference lib="dom" />

import * as types from "../src";

context("Types", () => {

  it("@peculiar WebCrypto matches DOM WebCrypto", () => {
    const myCrypto = {} as types.Crypto;
    let crypto: globalThis.Crypto = myCrypto;
  });

});