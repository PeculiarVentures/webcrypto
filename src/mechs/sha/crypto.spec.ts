import assert from "node:assert";
import { convert } from "@peculiar/utils";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("SHA3", () => {
  const data = new Uint8Array(10);
  it("SHA3-256", async () => {
    const digest = await crypto.subtle.digest("SHA3-256", data);
    assert.strictEqual(convert.encode("hex", digest), "0cd5285ba8524fe42ac8f0076de9135d056132a9996213ae1c0f1420c908418b");
  });
  it("SHA3-384", async () => {
    const digest = await crypto.subtle.digest("SHA3-384", data);
    assert.strictEqual(convert.encode("hex", digest), "f54cecb8c160015f87b9e51edd087e10479d60479a42ff7e907ddf129fd7cb2782eb5624c43b453a24cffd8cbe42d0ec");
  });
  it("SHA3-512", async () => {
    const digest = await crypto.subtle.digest("SHA3-512", data);
    assert.strictEqual(convert.encode("hex", digest), "e12f775adfb4e440b74af7b670849a44b7efd1612a97a3a201080cb31944f1f2d9f0eae6b7c0cdb602f6ff0ba181add9997fd06e43f992df577aa52153ca0d27");
  });
});
