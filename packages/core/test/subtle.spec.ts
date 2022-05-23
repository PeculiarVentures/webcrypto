import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";

context("SubtleCrypto", () => {

  class TestProvider extends core.ProviderCrypto {
    public name = "TEST";
    public usages: types.KeyUsage[] = ["sign", "verify", "deriveKey", "deriveBits", "encrypt", "decrypt", "wrapKey", "unwrapKey"];

    public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onGenerateKey(algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
      return key;
    }

    public override async onSign(algorithm: types.Algorithm, sKey: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onVerify(algorithm: types.Algorithm, sKey: core.CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
      return true;
    }

    public override async onEncrypt(algorithm: types.Algorithm, sKey: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onDecrypt(algorithm: types.Algorithm, sKey: core.CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onDeriveBits(algorithm: types.Algorithm, sKey: core.CryptoKey, length: number): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onExportKey(format: types.KeyFormat, sKey: core.CryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
      return new ArrayBuffer(0);
    }

    public override async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
      return key;
    }

  }

  // tslint:disable-next-line:max-classes-per-file
  class TestSubtleCrypto extends core.SubtleCrypto {
    constructor() {
      super();

      this.providers.set(new TestProvider());
    }
  }

  const subtle = new TestSubtleCrypto();
  const key = new core.CryptoKey();
  key.algorithm = { name: "TEST" };
  key.type = "secret",
    key.usages = ["sign", "verify", "deriveKey", "deriveBits", "encrypt", "decrypt", "wrapKey", "unwrapKey"];
  key.extractable = true;

  context("generateKey", () => {

    it("correct values", async () => {
      const res = await subtle.generateKey("test", false, ["sign"]);
      assert.equal(!!res, true);
    });

  });

  context("digest", () => {

    it("correct values", async () => {
      const res = await subtle.digest("test", new Uint8Array(0));
      assert.equal(!!res, true);
    });

  });

  context("sign", () => {

    it("correct values", async () => {
      const res = await subtle.sign({ name: "test", hash: "SHA-1" } as any, key, new Uint8Array(0));
      assert.equal(!!res, true);
    });

  });

  context("verify", () => {

    it("correct values", async () => {
      const res = await subtle.verify({ name: "test", hash: { name: "SHA-1" } } as any, key, new ArrayBuffer(0), new Uint8Array(0));
      assert.equal(!!res, true);
    });

  });

  context("encrypt", () => {

    it("correct values", async () => {
      const res = await subtle.encrypt("test", key, new Uint8Array(0));
      assert.equal(!!res, true);
    });

  });

  context("decrypt", () => {

    it("correct values", async () => {
      const res = await subtle.decrypt("test", key, new Uint8Array(0));
      assert.equal(!!res, true);
    });

  });

  context("deriveBits", () => {

    it("correct values", async () => {
      const res = await subtle.deriveBits("test", key, 128);
      assert.equal(!!res, true);
    });

  });

  context("deriveKey", () => {

    it("correct values", async () => {
      const res = await subtle.deriveKey("test", key, { name: "test", length: 128 } as any, false, ["verify"]);
      assert.equal(!!res, true);
    });

  });

  context("exportKey", () => {

    it("correct values", async () => {
      const res = await subtle.exportKey("raw", key);
      assert.equal(!!res, true);
    });

  });

  context("importKey", () => {

    it("correct values", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(0), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("json", async () => {
      const res = await subtle.importKey("jwk", { kty: "RSA" }, "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("Uint8Array", async () => {
      const res = await subtle.importKey("raw", new Uint8Array(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("Buffer", async () => {
      const res = await subtle.importKey("raw", Buffer.alloc(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

    it("ArrayBuffer", async () => {
      const res = await subtle.importKey("raw", new ArrayBuffer(10), "test", false, ["sign"]);
      assert.equal(!!res, true);
    });

  });

  context("wrapKey", () => {

    it("correct values", async () => {
      const res = await subtle.wrapKey("raw", key, key, "test");
      assert.equal(!!res, true);
    });

  });

  context("unwrapKey", () => {

    it("correct values", async () => {
      const res = await subtle.unwrapKey("raw", new ArrayBuffer(0), key, "test", "test", false, ["deriveKey"]);
      assert.equal(!!res, true);
    });

  });

  context("checkRequiredArguments", () => {

    it("error if less than required", async () => {
      await assert.rejects(subtle.digest.apply(subtle, ["test"] as unknown as any));
    });

    it("no error if greater than required", async () => {
      await assert.doesNotReject(subtle.digest.apply(subtle, ["test", new Uint8Array(0), 1, 2, 3]));
    });

  });

  context("getProvider", () => {
    it("error if there is not provider with given name", async () => {
      await assert.rejects(subtle.digest("wrong", new Uint8Array(0)));
    });
  });

  context("prepareData", () => {
    it("error if wrong data", async () => {
      await assert.rejects(subtle.digest("test", [1, 2, 3, 4] as any));
    });
    it("from Buffer", async () => {
      await subtle.digest("test", Buffer.from([1, 2, 3, 4]));
    });
  });

});
