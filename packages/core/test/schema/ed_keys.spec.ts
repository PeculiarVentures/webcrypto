import * as assert from "assert";
import { AsnConvert } from "@peculiar/asn1-schema";
import { JsonSerializer } from "@peculiar/json-schema";
import * as core from "@peculiar/webcrypto-core";
import { Convert } from "pvtsutils";

context("EdDSA and ECDH-ES keys", () => {

  it("Private key", () => {
    const b64 = "MEYCAQAwBQYDK2VvBDoEOPhm20uZC//c0wk1EEapNDcIIlgSGVxnWhwRJvT5K3+iwjtcyV2inuEihA5Soa5BO2OHh5leznW+";
    const raw = Buffer.from(b64, "base64");

    const pki = AsnConvert.parse(raw, core.asn1.PrivateKeyInfo);
    assert.strictEqual(pki.privateKeyAlgorithm.algorithm, core.asn1.idX448);
    const privateKey = AsnConvert.parse(pki.privateKey, core.asn1.CurvePrivateKey);

    assert.deepStrictEqual(JsonSerializer.toJSON(privateKey), { d: "-GbbS5kL_9zTCTUQRqk0NwgiWBIZXGdaHBEm9Pkrf6LCO1zJXaKe4SKEDlKhrkE7Y4eHmV7Odb4" });
  });

  it("Public key", () => {
    const b64 = "MCowBQYDK2VuAyEAR-a_Z6rz2HuBXn7m7v_pjef6nHfCWSIObVWCTr5nxjg";
    const raw = Convert.FromBase64Url(b64);

    const spki = AsnConvert.parse(raw, core.asn1.PublicKeyInfo);
    assert.strictEqual(spki.publicKeyAlgorithm.algorithm, core.asn1.idX25519);

    assert.strictEqual(Convert.ToBase64Url(spki.publicKey), "R-a_Z6rz2HuBXn7m7v_pjef6nHfCWSIObVWCTr5nxjg");
  });

});