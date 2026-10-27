import assert from "node:assert";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("ECDH deriveBits with null", () => {
  it("P-256", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: keyPair.publicKey.algorithm.name,
        public: keyPair.publicKey,
      } as globalThis.EcdhKeyDeriveParams,
      keyPair.privateKey,
      null as unknown as number,
    );
    assert.equal(bits.byteLength, 32);
  });

  it("P-384", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: keyPair.publicKey.algorithm.name,
        public: keyPair.publicKey,
      } as globalThis.EcdhKeyDeriveParams,
      keyPair.privateKey,
      null as unknown as number,
    );
    assert.equal(bits.byteLength, 48);
  });

  it("P-521", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-521",
      },
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: keyPair.publicKey.algorithm.name,
        public: keyPair.publicKey,
      } as globalThis.EcdhKeyDeriveParams,
      keyPair.privateKey,
      null as unknown as number,
    );
    assert.equal(bits.byteLength, 66);
  });
});
