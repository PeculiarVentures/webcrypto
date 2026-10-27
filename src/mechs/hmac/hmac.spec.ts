import assert from "node:assert";
import { describe, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

describe("HMAC", () => {
  it("Import Secret JWK without 'alg' and 'key_ops' fields", async () => {
    const aesKey = await crypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    );
    const jwk = await crypto.subtle.exportKey("jwk", aesKey);
    delete jwk.key_ops;
    delete jwk.alg;
    const hmacKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "HMAC",
        hash: "SHA-256",
      } as Algorithm,
      false,
      ["sign", "verify"],
    );
    assert.strictEqual(hmacKey.algorithm.name, "HMAC");
  });
});
