import { Buffer } from "node:buffer";
import nodeCrypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { Crypto } from "../../crypto";

const crypto = new Crypto();

// Ed25519/X25519 keys are kept as PEM internally; these pin the PEM <-> DER conversion.
describe.each([
  ["Ed25519", ["sign", "verify"], ["sign"], ["verify"]],
  ["X25519", ["deriveBits"], ["deriveBits"], []],
] as const)("%s PEM storage", (name, usages, privateUsages, publicUsages) => {
  it("exports the same DER as Node.js", async () => {
    const keys = (await crypto.subtle.generateKey({ name }, true, usages)) as CryptoKeyPair;
    const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", keys.privateKey));
    const spki = Buffer.from(await crypto.subtle.exportKey("spki", keys.publicKey));

    const privateKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    expect(privateKey.asymmetricKeyType).toBe(name.toLowerCase());
    expect(nodeCrypto.createPublicKey(privateKey).export({ format: "der", type: "spki" })).toEqual(spki);
  });

  it("round-trips pkcs8 and spki byte for byte", async () => {
    const node = nodeCrypto.generateKeyPairSync(name.toLowerCase() as "ed25519");
    const pkcs8 = node.privateKey.export({ format: "der", type: "pkcs8" });
    const spki = node.publicKey.export({ format: "der", type: "spki" });

    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name }, true, privateUsages);
    const publicKey = await crypto.subtle.importKey("spki", new Uint8Array(spki), { name }, true, publicUsages);
    expect(Buffer.from(await crypto.subtle.exportKey("pkcs8", privateKey))).toEqual(pkcs8);
    expect(Buffer.from(await crypto.subtle.exportKey("spki", publicKey))).toEqual(spki);
  });

  it("exports an imported private JWK as pkcs8", async () => {
    const node = nodeCrypto.generateKeyPairSync(name.toLowerCase() as "ed25519");
    const jwk = node.privateKey.export({ format: "jwk" });

    const key = await crypto.subtle.importKey("jwk", jwk, { name }, true, privateUsages);
    const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", key));
    expect(pkcs8).toEqual(node.privateKey.export({ format: "der", type: "pkcs8" }));
  });
});

describe("JWK base64url members", () => {
  // Same results as 1.7.1 (@peculiar/utils 2).
  it.each([
    ["padding", (v: string) => `${v}=`],
    ["base64 alphabet", (v: string) => `${v.slice(0, -1)}+`],
    ["invalid character", (v: string) => `*${v.slice(1)}`],
  ])("rejects an Ed25519 'd' with %s", async (_name, change) => {
    const jwk = nodeCrypto.generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
    await expect(crypto.subtle.importKey("jwk", { ...jwk, d: change(jwk.d!) }, { name: "Ed25519" }, true, ["sign"])).rejects.toThrow(TypeError);
  });
});
