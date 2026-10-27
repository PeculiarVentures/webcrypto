import assert from "node:assert";
import { Buffer } from "node:buffer";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("HKDF", () => {
  it("HKDF derive HMAC key", async () => {
    const hkdf = await crypto.subtle.importKey("raw", new Uint8Array([1, 2, 3, 4, 5]), { name: "HKDF" }, false, ["deriveKey"]);
    const hmac = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        info: new Uint8Array([1, 2, 3, 4, 5]),
        salt: new Uint8Array([1, 2, 3, 4, 5]),
      } as HkdfParams,
      hkdf,
      {
        name: "HMAC",
        hash: "SHA-1",
      } as globalThis.HmacImportParams,
      false,
      ["sign"],
    );
    assert.strictEqual((hmac.algorithm as globalThis.HmacKeyAlgorithm).length, 512);
  });
});

// Returns a view into a larger buffer, starting at offset 2.
function view(data: Buffer) {
  const padded = new Uint8Array(data.length + 4);
  padded.set(data, 2);
  return padded.subarray(2, 2 + data.length);
}

describe("HKDF deriveBits", () => {
  // RFC 5869, test case 1
  const ikm = Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex");
  const salt = Buffer.from("000102030405060708090a0b0c", "hex");
  const info = Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex");
  const okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

  const derive = async (params: { salt: BufferSource; info: BufferSource }) => {
    const key = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
    return crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", ...params }, key, okm.length * 4);
  };

  it("matches the RFC 5869 vector", async () => {
    const bits = await derive({ salt, info });
    assert.strictEqual(Buffer.from(bits).toString("hex"), okm);
  });

  it("reads salt and info views at their offsets", async () => {
    const bits = await derive({ salt: view(salt), info: new DataView(view(info).buffer, 2, info.length) });
    assert.strictEqual(Buffer.from(bits).toString("hex"), okm);
  });
});
