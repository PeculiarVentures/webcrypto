import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";

// tslint:disable:max-classes-per-file

class RsaSsaProvider extends core.RsaSsaProvider {
  public onSign(algorithm: core.RsaSsaParams, key: core.BaseCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onVerify(algorithm: core.RsaSsaParams, key: core.BaseCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    throw new Error("Method not implemented.");
  }
  public onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }
  public onExportKey(format: types.KeyFormat, key: core.BaseCryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    throw new Error("Method not implemented.");
  }
}

class RsaOaepProvider extends core.RsaOaepProvider {
  public onEncrypt(algorithm: types.RsaOaepParams, key: core.BaseCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onDecrypt(algorithm: types.RsaOaepParams, key: core.BaseCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public onGenerateKey(algorithm: types.RsaHashedKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    throw new Error("Method not implemented.");
  }
  public onExportKey(format: types.KeyFormat, key: core.BaseCryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.RsaHashedImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.BaseCryptoKey> {
    throw new Error("Method not implemented.");
  }
}

context("ProviderStorage", () => {

  it("set", () => {
    const storage = new core.ProviderStorage();

    assert.equal(storage.length, 0);

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());
    storage.set(new RsaOaepProvider());

    assert.equal(storage.length, 2);
  });

  it("get", () => {
    const storage = new core.ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const provider = storage.get("rsa-oaep");
    assert.equal(provider!.name, "RSA-OAEP");
  });

  it("has", () => {
    const storage = new core.ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    const ok = storage.has("rsa-oaep");
    assert.equal(ok, true);
  });

  it("algorithms", () => {
    const storage = new core.ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    assert.deepEqual(storage.algorithms, ["RSA-OAEP", "RSASSA-PKCS1-v1_5"]);
  });

  it("removeAt", () => {
    const storage = new core.ProviderStorage();

    storage.set(new RsaSsaProvider());
    storage.set(new RsaOaepProvider());

    storage.removeAt("rsa-wrong");
    assert.deepEqual(storage.length, 2);

    const removedProvider = storage.removeAt("rsa-oaep");
    assert.deepEqual(removedProvider!.name, "RSA-OAEP");
    assert.deepEqual(storage.length, 1);
  });

});
