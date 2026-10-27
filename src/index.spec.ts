import { describe, expect, it } from "vitest";
import * as webcrypto from "./index";
import { Crypto, CryptoKey } from "./index";

describe("public API", () => {
  it("exports Crypto and CryptoKey", () => {
    expect(Object.keys(webcrypto).sort()).toEqual(["Crypto", "CryptoKey"]);
  });

  // Also a type test: npm run typecheck compiles these calls the way consumers write them.
  it("works as the DOM Crypto type", async () => {
    const crypto: globalThis.Crypto = new Crypto();
    const data = crypto.getRandomValues(new Uint8Array(16));
    expect(crypto.randomUUID()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    expect(ec.privateKey).toBeInstanceOf(CryptoKey);
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ec.privateKey, data);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ec.publicKey, signature, data)).toBe(true);

    const jwk = await crypto.subtle.exportKey("jwk", ec.privateKey);
    const imported = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    expect(imported).toBeInstanceOf(CryptoKey);

    const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, data);
    expect(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aes, ciphertext))).toEqual(data);
  });

  it("keeps the generateKey overloads for typed parameters and readonly usages", async () => {
    const crypto = new Crypto();
    const algorithm: EcKeyGenParams = { name: "ECDH", namedCurve: "P-256" };
    const usages = ["deriveBits"] as const;
    const keys = await crypto.subtle.generateKey(algorithm, false, usages);
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: keys.publicKey }, keys.privateKey, 256);
    expect(bits.byteLength).toBe(32);
  });
});
