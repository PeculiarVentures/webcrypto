import { Crypto as NodeCrypto } from "@peculiar/webcrypto";
import { Crypto as WebCrypto } from "@peculiar/webcrypto-web";
import * as assert from "assert";

const nodeCrypto = new NodeCrypto();
const webCrypto = new WebCrypto();

context("ED", () => {

  context("generate/export/import/sign/verify", () => {
    const alg = { name: "EdDSA", namedCurve: "Ed25519" };
    const data = Buffer.from("Some message to sign");

    it("pkcs8/spki", async () => {
      const linerKeys = await webCrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      const pkcs8 = await webCrypto.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const spki = await webCrypto.subtle.exportKey("spki", linerKeys.publicKey);

      const nodePrivateKey = await nodeCrypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const nodePublicKey = await nodeCrypto.subtle.importKey("spki", spki, alg, false, ["verify"]);
      const linerPrivateKey = await webCrypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const linerPublicKey = await webCrypto.subtle.importKey("spki", spki, alg, false, ["verify"]);

      const nodeSignature = await nodeCrypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await webCrypto.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await nodeCrypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await webCrypto.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

    it("jwk", async () => {
      const linerKeys = await webCrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      const privateJwk = await webCrypto.subtle.exportKey("jwk", linerKeys.privateKey);
      const publicJwk = await webCrypto.subtle.exportKey("jwk", linerKeys.publicKey);

      const nodePrivateKey = await nodeCrypto.subtle.importKey("jwk", privateJwk, alg, false, ["sign"]);
      const nodePublicKey = await nodeCrypto.subtle.importKey("jwk", publicJwk, alg, false, ["verify"]);
      const linerPrivateKey = await webCrypto.subtle.importKey("jwk", privateJwk, alg, false, ["sign"]);
      const linerPublicKey = await webCrypto.subtle.importKey("jwk", publicJwk, alg, false, ["verify"]);

      const nodeSignature = await nodeCrypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await webCrypto.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await nodeCrypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await webCrypto.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

    it("pkcs8/raw", async () => {
      const linerKeys = await webCrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      const pkcs8 = await webCrypto.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const raw = await webCrypto.subtle.exportKey("raw", linerKeys.publicKey);

      const nodePrivateKey = await nodeCrypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const nodePublicKey = await nodeCrypto.subtle.importKey("raw", raw, alg, false, ["verify"]);
      const linerPrivateKey = await webCrypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const linerPublicKey = await webCrypto.subtle.importKey("raw", raw, alg, false, ["verify"]);

      const nodeSignature = await nodeCrypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await webCrypto.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await nodeCrypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await webCrypto.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

  });

});
