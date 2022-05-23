import * as core from "@peculiar/webcrypto-core";
import * as assert from "assert";
import { Convert } from "pvtsutils";

context("PemConverter", () => {

  // tslint:disable-next-line:max-line-length
  const bytes = Convert.FromHex("30819f300d06092a864886f70d010101050003818d0030818902818100f615b745314ffe4669255dfe68953184bb8e5db54eecd35b4c51ee899ce7e60aaf19cc765d924f94be93d6809ba506fab26b9f8ef0cf6ab2aec1942da222992f8dad2e621845f014f9e831a529665faf0a9b8ca97356a602ce8d17cd3469aafa2de82546773540fa480510d1906c78c87b81850c26fdaeccce37cd5fdeba7e050203010001");
  // tslint:disable-next-line:prefer-template
  const vector = "-----BEGIN PUBLIC KEY-----\n" +
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2FbdFMU/+RmklXf5olTGEu45d\n" +
    "tU7s01tMUe6JnOfmCq8ZzHZdkk+UvpPWgJulBvqya5+O8M9qsq7BlC2iIpkvja0u\n" +
    "YhhF8BT56DGlKWZfrwqbjKlzVqYCzo0XzTRpqvot6CVGdzVA+kgFENGQbHjIe4GF\n" +
    "DCb9rszON81f3rp+BQIDAQAB\n" +
    "-----END PUBLIC KEY-----";

  it("fromBufferSource", () => {
    const pem = core.PemConverter.fromBufferSource(bytes, "public key");

    assert.equal(pem, vector);
  });

  it("fromBufferSource multiple 64", () => {
    const pem = core.PemConverter.fromBufferSource(Buffer.from("1234567890abcdef1234567890abcdef1234567890abcdef"), "public key");

    assert.equal(pem, "-----BEGIN PUBLIC KEY-----\n" +
      "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVm\n" +
      "-----END PUBLIC KEY-----");
  });

  it("toArrayBuffer", () => {
    const buf = core.PemConverter.toArrayBuffer(vector);

    assert.equal(Convert.ToHex(buf), Convert.ToHex(bytes));
  });

  it("toUint8Array", () => {
    const buf = core.PemConverter.toUint8Array(vector);

    assert.equal(Convert.ToHex(buf), Convert.ToHex(bytes));
  });

  context("isPEM", () => {
    // tslint:disable-next-line:prefer-template
    const pem = "-----BEGIN CERTIFICATE------\n" +
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\n" +
      "-----END CERTIFICATE------";

    it("return true if correct PEM", () => {
      assert.equal(core.PemConverter.isPEM(pem), true);
    });

    it("return true if inline PEM", () => {
      assert.equal(core.PemConverter.isPEM(pem.replace(/\n/g, "")), true);
    });

    it("return false if correct PEM", () => {
      // tslint:disable-next-line:prefer-template
      const wrongPem = "----- BEGIN CERTIFICATE ------\n" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\n" +
        "----- END CERTIFICATE ------";
      assert.equal(core.PemConverter.isPEM(wrongPem), false);
    });

  });

  context("getTagName", () => {

    it("get tag name from spki", () => {
      const tagName = core.PemConverter.getTagName(vector);
      assert.equal(tagName, "PUBLIC KEY");
    });

    it("throw error if data is wrong PEM", () => {
      assert.throws(() => core.PemConverter.getTagName("----- BEGIN CERTIFICATE ------"));
    });

  });

  context("hasTagName", () => {

    it("return true if tag names are equal", () => {
      assert.equal(core.PemConverter.hasTagName(vector, "public key"), true);
    });

    it("return false if tag names are not equal", () => {
      assert.equal(core.PemConverter.hasTagName(vector, "PRIVATE KEY"), false);
    });

  });

  it("isCertificate", () => {
    const pem = core.PemConverter.fromBufferSource(new Uint8Array([1, 0, 1]), "certificate");
    assert.equal(core.PemConverter.isCertificate(pem), true);
  });

  it("isCRL", () => {
    const pem = core.PemConverter.fromBufferSource(new Uint8Array([1, 0, 1]), "X509 CRL");
    assert.equal(core.PemConverter.isCRL(pem), true);
  });

  it("isCertificateRequest", () => {
    const pem = core.PemConverter.fromBufferSource(new Uint8Array([1, 0, 1]), "certificate request");
    assert.equal(core.PemConverter.isCertificateRequest(pem), true);
  });

  it("isPublicKey", () => {
    const pem = core.PemConverter.fromBufferSource(new Uint8Array([1, 0, 1]), "public key");
    assert.equal(core.PemConverter.isPublicKey(pem), true);
  });

});
