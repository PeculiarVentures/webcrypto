import assert from "assert";
import { WebcryptoTest } from "@peculiar/webcrypto-test";
import * as core from "webcrypto-core";
import { Crypto } from "../src";

const crypto = new Crypto();

WebcryptoTest.check(crypto as any, {});
context("Crypto", () => {


  context("getRandomValues", () => {

    it("Uint8Array", () => {
      const array = new Uint8Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "0000000000");
      assert.strictEqual(Buffer.from(array2).equals(array), true);
    });

    it("Uint16Array", () => {
      const array = new Uint16Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "00000000000000000000");
      assert.strictEqual(Buffer.from(array2).equals(Buffer.from(array)), true);
    });

  });

  it("Import wrong named curve", async () => {
    const spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzlbSDQWz+1nwEHsrT516OAEX5YWzwVYj39BH+Rv5yoP9yLgM5wIXgOls5DoLDJVQ+45XDrD/xjSCcul5NACZw==", "base64");
    await assert.rejects(crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "K-256" } as Algorithm,
      false,
      ["verify"]), core.CryptoError);
  });

});
