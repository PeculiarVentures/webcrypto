import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import * as pvtsutils from "pvtsutils";
import { BrowserInfo } from "../../src/helper";

// fix type errors
type Crypto = any;

export const browser = BrowserInfo();

export interface ITestMochaFunction {
  skip?: boolean;
  only?: boolean;
}

export interface ITestAction extends ITestMochaFunction {
  name?: string;
  error?: any;
}

export interface ITestGenerateKeyAction extends ITestAction {
  algorithm: types.Algorithm;
  extractable: boolean;
  keyUsages: types.KeyUsage[];
}

export interface IImportKeyParams {
  format: types.KeyFormat;
  data: types.JsonWebKey | types.BufferSource;
  algorithm: types.AlgorithmIdentifier;
  extractable: boolean;
  keyUsages: types.KeyUsage[];
}

export interface IImportKeyPairParams {
  privateKey: IImportKeyParams;
  publicKey: IImportKeyParams;
}

export interface ITestEncryptAction extends ITestAction {
  algorithm: types.Algorithm;
  data: types.BufferSource;
  encData: types.BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestSignAction extends ITestAction {
  algorithm: types.Algorithm;
  data: types.BufferSource;
  signature: types.BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestDeriveBitsAction extends ITestAction {
  algorithm: types.Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  data: types.BufferSource;
  length: number;
}

export interface ITestDeriveKeyAction extends ITestAction {
  algorithm: types.Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  derivedKeyType: types.Algorithm;
  keyUsages: types.KeyUsage[];
  format: types.KeyFormat;
  keyData: types.BufferSource | types.JsonWebKey;
}

export interface ITestWrapKeyAction extends ITestAction {
  key: IImportKeyParams | IImportKeyPairParams;
  algorithm: types.Algorithm;
  wKey: IImportKeyParams;
  wrappedKey?: types.BufferSource;
}

export interface ITestImportAction extends IImportKeyParams, ITestAction {
}

export interface ITestDigestAction extends ITestAction {
  algorithm: types.AlgorithmIdentifier;
  data: types.BufferSource;
  hash: types.BufferSource;
}

export interface ITestActions {
  generateKey?: ITestGenerateKeyAction[];
  encrypt?: ITestEncryptAction[];
  wrapKey?: ITestWrapKeyAction[];
  sign?: ITestSignAction[];
  import?: ITestImportAction[];
  deriveBits?: ITestDeriveBitsAction[];
  deriveKey?: ITestDeriveKeyAction[];
  digest?: ITestDigestAction[];
}

export interface ITestParams extends ITestMochaFunction {
  name: string;
  actions: ITestActions;
}

async function getKeys(crypto: Crypto, key: IImportKeyParams | IImportKeyPairParams) {
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

function wrapSkipOnly(item: Mocha.TestFunction, params: ITestMochaFunction): Mocha.PendingTestFunction;
function wrapSkipOnly(item: Mocha.SuiteFunction, params: ITestMochaFunction): Mocha.PendingSuiteFunction;
function wrapSkipOnly(item: Mocha.TestFunction | Mocha.SuiteFunction, params: ITestMochaFunction) {
  return params.skip
    ? item.skip
    : params.only
      ? item.only
      : item;
}

async function wrapTest(promise: () => Promise<void>, action: ITestAction, index: number) {
  wrapSkipOnly(it, action)(action.name || `#${index + 1}`, async () => {
    if (action.error) {
      if (typeof (action.error) === "boolean") {
        await assert.rejects(promise());
      } else {
        await assert.rejects(promise(), action.error);
      }
    } else {
      await promise();
    }
  });
}

export function testCrypto(crypto: Crypto, params: ITestParams[]) {
  params.forEach((param) => {
    wrapSkipOnly(context, param)(param.name, () => {
      //#region Generate key
      if (param.actions.generateKey) {
        context("Generate Key", () => {
          param.actions.generateKey!.forEach((action, index) => {
            wrapTest(async () => {
              const algorithm = Object.assign({}, action.algorithm);
              algorithm.name = algorithm.name.toLowerCase();

              const key = await crypto.subtle.generateKey(
                algorithm,
                action.extractable,
                action.keyUsages,
              );

              assert.equal(!!key, true);
              if (!key.privateKey) {
                assert.equal(key.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                assert.equal(key.extractable, action.extractable);
                assert.deepEqual([...key.usages].sort(), [...action.keyUsages].sort());

              } else {
                assert.equal(!!key.privateKey, true);
                assert.equal(key.privateKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                assert.equal(key.privateKey.extractable, action.extractable);

                assert.equal(!!key.publicKey, true);
                assert.equal(key.publicKey.algorithm.name, action.algorithm.name, "Algorithm name MUST be equal to incoming algorithm and in the same case");
                assert.equal(key.publicKey.extractable, true);
              }
            }, action, index);
          });
        });
      }
      //#endregion

      //#region encrypt
      if (param.actions.encrypt) {
        context("Encrypt/Decrypt", () => {
          param.actions.encrypt!.forEach((action, index) => {
            wrapTest(async () => {
              // import keys
              const keys = await getKeys(crypto, action.key);
              const encKey = keys.publicKey;
              const decKey = keys.privateKey;

              const algorithm = Object.assign({}, action.algorithm);
              algorithm.name = algorithm.name.toLowerCase();

              // encrypt
              const enc = await crypto.subtle.encrypt(algorithm, encKey, action.data);
              // decrypt
              let dec = await crypto.subtle.decrypt(algorithm, decKey, enc);
              assert.equal(pvtsutils.Convert.ToHex(dec), pvtsutils.Convert.ToHex(action.data));

              dec = await crypto.subtle.decrypt(algorithm, decKey, action.encData);
              assert.equal(pvtsutils.Convert.ToHex(dec), pvtsutils.Convert.ToHex(action.data));
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Import/Export
      if (param.actions.import) {
        context("Import/Export", () => {
          param.actions.import!.forEach((action, index) => {
            wrapTest(async () => {
              const importedKey = await crypto.subtle.importKey(
                action.format,
                action.data,
                action.algorithm,
                action.extractable,
                action.keyUsages);

              // Can't continue if key is not extractable.
              if (!action.extractable) {
                return;
              }

              const exportedData = await crypto.subtle.exportKey(
                action.format,
                importedKey);

              if (action.format === "jwk") {
                exportedData.key_ops.sort();
                (action.data as Required<types.JsonWebKey>).key_ops.sort();
                assert.deepEqual(exportedData, action.data);
              } else {
                assert.equal(pvtsutils.Convert.ToHex(exportedData as ArrayBuffer), pvtsutils.Convert.ToHex(action.data as ArrayBuffer));
              }
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Sign/Verify
      if (param.actions.sign) {
        context("Sign/Verify", () => {
          param.actions.sign!.forEach((action, index) => {
            wrapTest(async () => {
              // import keys
              const keys = await getKeys(crypto, action.key);
              const verifyKey = keys.publicKey;
              const signKey = keys.privateKey;

              const algorithm = Object.assign({}, action.algorithm);
              algorithm.name = algorithm.name.toLowerCase();

              // sign
              const signature = await crypto.subtle.sign(algorithm, signKey, action.data);
              // verify
              let ok = await crypto.subtle.verify(algorithm, verifyKey, signature, action.data);
              assert.equal(true, ok, "Cannot verify signature from Action data");

              ok = await crypto.subtle.verify(algorithm, verifyKey, action.signature, action.data);
              if (!ok) {
                assert.equal(pvtsutils.Convert.ToHex(signature), pvtsutils.Convert.ToHex(action.signature));
              }
              assert.equal(true, ok);
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Derive bits
      if (param.actions.deriveBits) {
        context("Derive bits", () => {
          param.actions.deriveBits!.forEach((action, index) => {
            wrapTest(async () => {
              // import keys
              const keys = await getKeys(crypto, action.key);

              const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey });
              algorithm.name = algorithm.name.toLowerCase();

              // derive bits
              const derivedBits = await crypto.subtle.deriveBits(algorithm, keys.privateKey, action.length);
              assert.equal(pvtsutils.Convert.ToHex(derivedBits), pvtsutils.Convert.ToHex(action.data));
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Derive key
      if (param.actions.deriveKey) {
        context("Derive key", () => {
          param.actions.deriveKey!.forEach((action, index) => {
            wrapTest(async () => {
              // import keys
              const keys = await getKeys(crypto, action.key);

              const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey });
              algorithm.name = algorithm.name.toLowerCase();

              // derive key
              const derivedKey = await crypto.subtle.deriveKey(algorithm, keys.privateKey, action.derivedKeyType, true, action.keyUsages);
              const keyData = await crypto.subtle.exportKey(action.format, derivedKey);
              if (action.format === "jwk") {
                assert.deepEqual(keyData, action.keyData);
              } else {
                assert.equal(pvtsutils.Convert.ToHex(keyData as ArrayBuffer), pvtsutils.Convert.ToHex(action.keyData as ArrayBuffer));
              }
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Digest
      if (param.actions.digest) {
        context("Digest", () => {
          param.actions.digest!.forEach((action, index) => {
            wrapTest(async () => {
              const hash = await crypto.subtle.digest(action.algorithm, action.data);
              assert.equal(pvtsutils.Convert.ToHex(hash), pvtsutils.Convert.ToHex(action.hash));
            }, action, index);
          });
        });
      }
      //#endregion

      //#region Wrap/Unwrap key
      if (param.actions.wrapKey) {
        context("Wrap/Unwrap key", () => {
          param.actions.wrapKey!.forEach((action, index) => {
            wrapTest(async () => {
              const wKey = (await getKeys(crypto, action.wKey)).privateKey;
              const key = await getKeys(crypto, action.key);

              const wrappedKey = await crypto.subtle.wrapKey(action.wKey.format, wKey, key.publicKey, action.algorithm);

              if (action.wrappedKey) {
                assert.equal(pvtsutils.Convert.ToHex(wrappedKey), pvtsutils.Convert.ToHex(action.wrappedKey));
              }

              const unwrappedKey = await crypto.subtle.unwrapKey(
                action.wKey.format,
                wrappedKey,
                key.privateKey,
                action.algorithm,
                action.wKey.algorithm,
                action.wKey.extractable,
                action.wKey.keyUsages);

              assert.deepEqual(unwrappedKey.algorithm, wKey.algorithm);
            }, action, index);
          });
        });
      }
      //#endregion
    });
  });
}
