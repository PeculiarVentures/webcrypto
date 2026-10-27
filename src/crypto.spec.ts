import assert from "node:assert";
import { Buffer } from "node:buffer";
import { describe, it } from "vitest";
import { Crypto } from "./crypto";

const crypto = new Crypto();

describe("Crypto", () => {
  describe("getRandomValues", () => {
    it("Uint8Array", () => {
      const array = new Uint8Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "0000000000");
      assert.strictEqual(Buffer.from(array2).equals(array), true);
    });

    it("Uint8Array subarray", () => {
      const array = new Uint8Array(10);
      const subarray = array.subarray(0, 5);
      const array2 = crypto.getRandomValues(subarray);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "00000000000000000000");
      assert.strictEqual(subarray, array2);
      assert.ok(Buffer.from(array).toString("hex").endsWith("0000000000"));
    });

    it("Uint16Array", () => {
      const array = new Uint16Array(5);
      const array2 = crypto.getRandomValues(array);

      assert.notStrictEqual(Buffer.from(array).toString("hex"), "00000000000000000000");
      assert.strictEqual(Buffer.from(array2).equals(Buffer.from(array)), true);
    });
  });
});
