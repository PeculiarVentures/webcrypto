
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { Convert } from "pvtsutils";
import * as testTypes from "./types";

/**
 * Gets keys
 * @param crypto
 * @param key
 */
async function getKeys(crypto: types.Crypto, key: testTypes.IImportKeyParams | testTypes.IImportKeyPairParams) {
  const keys = {} as types.CryptoKeyPair;
  if ("privateKey" in key) {
    keys.privateKey = await crypto.subtle.importKey(
      key.privateKey.format,
      key.privateKey.data,
      key.privateKey.algorithm,
      key.privateKey.extractable,
      key.privateKey.keyUsages);
    keys.publicKey = await crypto.subtle.importKey(
      key.publicKey.format,
      key.publicKey.data,
      key.publicKey.algorithm,
      key.publicKey.extractable,
      key.publicKey.keyUsages);
  } else {
    keys.privateKey = keys.publicKey = await crypto.subtle.importKey(
      key.format,
      key.data,
      key.algorithm,
      key.extractable,
      key.keyUsages);
  }
  return keys;
}

async function wrapTest(promise: () => Promise<void>, action: testTypes.ITestAction, index: number) {
  const test = action.skip
    ? it.skip
    : action.only
      ? it.only
      : it;

  test(action.name || `#${index + 1}`, async () => {
    if (action.error) {
      await assert.rejects(promise(), action.error);
    } else {
      await promise();
    }
  });
}

function isKeyPair(obj: any): obj is types.CryptoKeyPair {
  return obj.privateKey && obj.publicKey;
}

function testGenerateKey(generateKey: testTypes.ITestGenerateKeyAction[], crypto: types.Crypto) {
  context("Generate Key", () => {
    generateKey.forEach((action, index) => {
      wrapTest(async () => {
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        const key = await crypto.subtle.generateKey(algorithm, action.extractable, action.keyUsages);
        assert(key);
        if (!isKeyPair(key)) {
          assert.equal(key.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(key.extractable, action.extractable);
          assert.deepEqual(key.usages, action.keyUsages);
        } else {
          assert(key.privateKey);
          assert.equal(key.privateKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(key.privateKey.extractable, action.extractable);
          assert(key.publicKey);
          assert.equal(key.publicKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
          assert.equal(key.publicKey.extractable, true);
        }
        action.assert?.(key);
      }, action, index);
    });
  });
}

function testImport(importFn: testTypes.ITestImportAction[], crypto: types.Crypto) {
  context("Import/Export", () => {
    importFn.forEach((action, index) => {
      wrapTest(async () => {
        // @ts-ignore
        const importedKey = await crypto.subtle.importKey(action.format, action.data, action.algorithm, action.extractable, action.keyUsages);
        // Can't continue if key is not extractable.
        if (!action.extractable) {
          return;
        }
        const exportedData = await crypto.subtle.exportKey(action.format, importedKey);
        if (action.format === "jwk") {
          assert.deepEqual(exportedData, action.data);
        } else {
          assert.equal(Buffer.from(exportedData as ArrayBuffer).toString("hex"), Buffer.from(action.data as ArrayBuffer).toString("hex"));
        }
        action.assert?.(importedKey);
      }, action, index);
    });
  });
}

function testSign(sign: testTypes.ITestSignAction[], crypto: types.Crypto) {
  context("Sign/Verify", () => {
    sign.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const verifyKey = keys.publicKey;
        const signKey = keys.privateKey;
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        // sign
        // @ts-ignore
        const signature = await crypto.subtle.sign(algorithm, signKey, action.data);
        // verify
        // @ts-ignore
        let ok = await crypto.subtle.verify(algorithm, verifyKey, signature, action.data);
        assert.equal(true, ok, "Cannot verify signature from Action data");
        // @ts-ignore
        ok = await crypto.subtle.verify(algorithm, verifyKey, action.signature, action.data);
        if (!ok) {
          assert.equal(Convert.ToHex(signature), Convert.ToHex(action.signature));
        }
        assert.equal(true, ok);
      }, action, index);
    });
  });
}

function testDeriveBits(deriveBits: testTypes.ITestDeriveBitsAction[], crypto: types.Crypto) {
  context("Derive bits", () => {
    deriveBits.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
        algorithm.name = algorithm.name.toLowerCase();
        // derive bits
        const derivedBits = await crypto.subtle.deriveBits(algorithm, keys.privateKey, action.length);
        assert.equal(Convert.ToHex(derivedBits), Convert.ToHex(action.data));
      }, action, index);
    });
  });
}

function testDeriveKey(deriveKey: testTypes.ITestDeriveKeyAction[], crypto: types.Crypto) {
  context("Derive key", () => {
    deriveKey.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
        algorithm.name = algorithm.name.toLowerCase();
        // derive key
        // @ts-ignore
        const derivedKey = await crypto.subtle.deriveKey(algorithm, keys.privateKey, action.derivedKeyType, true, action.keyUsages);
        const keyData = await crypto.subtle.exportKey(action.format, derivedKey);
        if (action.format === "jwk") {
          assert.deepEqual(keyData, action.keyData);
        } else {
          assert.equal(Convert.ToHex(keyData as ArrayBuffer), Convert.ToHex(action.keyData as ArrayBuffer));
        }
        action.assert?.(derivedKey);
      }, action, index);
    });
  });
}

function testWrap(wrapKey: testTypes.ITestWrapKeyAction[], crypto: types.Crypto) {
  context("Wrap/Unwrap key", () => {
    wrapKey.forEach((action, index) => {
      wrapTest(async () => {
        const wKey = (await getKeys(crypto, action.wKey)).privateKey;
        const key = await getKeys(crypto, action.key);
        const wrappedKey = await crypto.subtle.wrapKey(action.wKey.format, wKey, key.publicKey, action.algorithm);
        if (action.wrappedKey) {
          assert.equal(Convert.ToHex(wrappedKey), Convert.ToHex(action.wrappedKey));
        }
        const unwrappedKey = await crypto.subtle.unwrapKey(action.wKey.format, wrappedKey, key.privateKey, action.algorithm, action.wKey.algorithm, action.wKey.extractable, action.wKey.keyUsages);
        assert.deepEqual(unwrappedKey.algorithm, wKey.algorithm);
      }, action, index);
    });
  });
}

function testDigest(digest: testTypes.ITestDigestAction[], crypto: types.Crypto) {
  context("Digest", () => {
    digest.forEach((action, index) => {
      wrapTest(async () => {
        // @ts-ignore
        const hash = await crypto.subtle.digest(action.algorithm, action.data);
        assert.equal(Convert.ToHex(hash), Convert.ToHex(action.hash));
      }, action, index);
    });
  });
}

function testEncrypt(encrypt: testTypes.ITestEncryptAction[], crypto: types.Crypto) {
  context("Encrypt/Decrypt", () => {
    encrypt.forEach((action, index) => {
      wrapTest(async () => {
        // import keys
        const keys = await getKeys(crypto, action.key);
        const encKey = keys.publicKey;
        const decKey = keys.privateKey;
        const algorithm = Object.assign({}, action.algorithm);
        algorithm.name = algorithm.name.toLowerCase();
        // encrypt
        // @ts-ignore
        const enc = await crypto.subtle.encrypt(algorithm, encKey, action.data);
        // decrypt
        let dec = await crypto.subtle.decrypt(algorithm, decKey, enc);
        assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));
        // @ts-ignore
        dec = await crypto.subtle.decrypt(algorithm, decKey, action.encData);
        assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));
      }, action, index);
    });
  });
}

export function testCrypto(crypto: types.Crypto, param: testTypes.ITestParams) {
  context(param.name, () => {

    if (param.actions.generateKey) {
      testGenerateKey(param.actions.generateKey, crypto);
    }

    if (param.actions.encrypt) {
      testEncrypt(param.actions.encrypt, crypto);
    }

    if (param.actions.import) {
      testImport(param.actions.import, crypto);
    }

    if (param.actions.sign) {
      testSign(param.actions.sign, crypto);
    }

    if (param.actions.deriveBits) {
      testDeriveBits(param.actions.deriveBits, crypto);
    }

    if (param.actions.deriveKey) {
      testDeriveKey(param.actions.deriveKey, crypto);
    }

    const digest = param.actions.digest;
    if (digest) {
      testDigest(digest, crypto);
    }

    const wrapKey = param.actions.wrapKey;
    if (wrapKey) {
      testWrap(wrapKey, crypto);
    }
  });
}