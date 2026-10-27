import { describe, expect, it } from "vitest";
import { Crypto } from "../crypto";

const crypto = new Crypto();

describe("JWK alg", () => {
  const cases: [string, AesKeyGenParams | HmacKeyGenParams, KeyUsage[]][] = [
    ["A128CBC", { name: "AES-CBC", length: 128 }, ["encrypt"]],
    ["A192CTR", { name: "AES-CTR", length: 192 }, ["encrypt"]],
    ["A256GCM", { name: "AES-GCM", length: 256 }, ["encrypt"]],
    ["A256KW", { name: "AES-KW", length: 256 }, ["wrapKey"]],
    ["A128ECB", { name: "AES-ECB", length: 128 }, ["encrypt"]],
    ["A256CMAC", { name: "AES-CMAC", length: 256 }, ["sign"]],
    ["HS1", { name: "HMAC", hash: "SHA-1" }, ["sign"]],
    ["HS256", { name: "HMAC", hash: "SHA-256" }, ["sign"]],
    ["HS512", { name: "HMAC", hash: "SHA-512" }, ["sign"]],
    ["3DES-CBC", { name: "DES-EDE3-CBC", length: 192 }, ["encrypt"]],
  ];

  it.each(cases)("exports %s", async (alg, algorithm, usages) => {
    const key = (await crypto.subtle.generateKey(algorithm, true, usages)) as CryptoKey;
    const jwk = await crypto.subtle.exportKey("jwk", key);
    expect(jwk.alg).toBe(alg);

    // An imported key exports the same alg
    const imported = await crypto.subtle.importKey("jwk", jwk, algorithm, true, usages);
    expect((await crypto.subtle.exportKey("jwk", imported)).alg).toBe(alg);
  });

  const nativeCases: [string, AesKeyGenParams | HmacKeyGenParams, KeyUsage[]][] = [
    ["AES-GCM", { name: "AES-GCM", length: 256 }, ["encrypt"]],
    ["HMAC", { name: "HMAC", hash: "SHA-384" }, ["sign"]],
  ];

  it.each(nativeCases)("matches Node.js WebCrypto for %s", async (_name, algorithm, usages) => {
    const key = (await crypto.subtle.generateKey(algorithm, true, usages)) as CryptoKey;
    const native = (await globalThis.crypto.subtle.generateKey(algorithm, true, usages)) as CryptoKey;
    expect((await crypto.subtle.exportKey("jwk", key)).alg).toBe((await globalThis.crypto.subtle.exportKey("jwk", native)).alg);
  });
});
