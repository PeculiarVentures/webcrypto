import assert from "node:assert";
import { Buffer } from "node:buffer";
import * as core from "webcrypto-core";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("shake digest", () => {
  const data = Buffer.from("test data");

  describe("shake128", () => {
    it("default", async () => {
      const hash = await crypto.subtle.digest("shake128", data);

      assert.strictEqual(Buffer.from(hash).toString("hex"), "ae3bdcf04986a8e7ddd99ac948254693");
    });

    it("128 byte length", async () => {
      const hash = await crypto.subtle.digest(
        {
          name: "shake128",
          length: 128,
        } as core.ShakeParams,
        data,
      );

      assert.strictEqual(
        Buffer.from(hash).toString("hex"),
        "ae3bdcf04986a8e7ddd99ac948254693fc32ca6ce3ed278c0c54127f072ba21e977d76aa76cab8f85f61c3e1fb7dab42c6b96d39f96fbd8cdcba7121e28cc97bb51f277a00398f99a9e6f11d027473cbffb3ac4ce444e2e8284caeca4e62f725d340fa3519eec7ca3eb4188607c26b0ecdf3750beba8882d6f2b734960cca914",
      );
    });
  });

  describe("shake256", () => {
    it("default", async () => {
      const hash = await crypto.subtle.digest("shake256", data);

      assert.strictEqual(Buffer.from(hash).toString("hex"), "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e26");
    });

    it("256 byte length", async () => {
      const hash = await crypto.subtle.digest(
        {
          name: "shake256",
          length: 256,
        } as core.ShakeParams,
        data,
      );

      assert.strictEqual(
        Buffer.from(hash).toString("hex"),
        "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e262dd68c2a2f932847f9610eeb51f8ba1a180ca878c788e900d899538d45c9c4a6f1bf10d8502a7ccbd9fd540bd856591000700e10130673ef970ffb788afe08426648a216d032733b71e85f128f1ed9e4c8bd910b5000e8c381afb45735680eaf7cb5bf1ae4265ee0822dfe6a9426ff21e309398df57cbf5861f5947f3d261e2d4517ff0d1be988e7014a09c4312d37010cf0e47468c1cf832e6a61e9d9fe3b67e6ab265cb6d95ad7a1f863d71e0e6ed5cd17d568b86e99d84bdb970a580f551017b501ae6761d2d6de76a64385dc10f27d18c2564a6bfbfb1e3f335010bebdf8",
      );
    });
  });
});
