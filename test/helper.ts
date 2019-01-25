import assert from "assert";
import { Convert } from "pvtsutils";
import { Crypto, CryptoKey } from "webcrypto-core";

/**
 * Returns true if blobs from keys are equal
 * @param a Crypto key
 * @param b Crypto key
 */
export function isKeyEqual(a: CryptoKey, b: CryptoKey) {
  if (a instanceof CryptoKey && b instanceof CryptoKey) {
    return (a as any).data.equals((b as any).data);
  }
  return false;
}

export interface ITestAction {
  name?: string;
  only?: boolean;
  skip?: boolean;
  error?: any;
}

export interface ITestGenerateKeyAction extends ITestAction {
  algorithm: Algorithm;
  extractable: boolean;
  keyUsages: KeyUsage[];
}

export interface IImportKeyParams {
  format: KeyFormat;
  data: JsonWebKey | BufferSource;
  algorithm: AlgorithmIdentifier;
  extractable: boolean;
  keyUsages: KeyUsage[];
}

export interface IImportKeyPairParams {
  privateKey: IImportKeyParams;
  publicKey: IImportKeyParams;
}

export interface ITestEncryptAction extends ITestAction {
  algorithm: Algorithm;
  data: BufferSource;
  encData: BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestSignAction extends ITestAction {
  algorithm: Algorithm;
  data: BufferSource;
  signature: BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestDeriveBitsAction extends ITestAction {
  algorithm: Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  data: BufferSource;
  length: number;
}

export interface ITestDeriveKeyAction extends ITestAction {
  algorithm: Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  derivedKeyType: Algorithm;
  keyUsages: KeyUsage[];
  format: KeyFormat;
  keyData: BufferSource | JsonWebKey;
}

export interface ITestWrapKeyAction extends ITestAction {
  key: IImportKeyParams | IImportKeyPairParams;
  algorithm: Algorithm;
  wKey: IImportKeyParams;
}

export interface ITestImportAction extends IImportKeyParams, ITestAction {
}

export interface ITestDigestAction extends ITestAction {
  algorithm: AlgorithmIdentifier;
  data: BufferSource;
  hash: BufferSource;
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

export interface ITestParams {
  name: string;
  only?: boolean;
  actions: ITestActions;
}

async function getKeys(crypto: Crypto, key: IImportKeyParams | IImportKeyPairParams) {
  const keys = {} as CryptoKeyPair;
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

async function wrapTest(promise: () => Promise<void>, action: ITestAction, index: number) {
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

export function testCrypto(crypto: Crypto, params: ITestParams[]) {
  params.forEach((param) => {
    context(param.name, () => {
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

              assert(key);
              if (key instanceof CryptoKey) {
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
              assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));

              dec = await crypto.subtle.decrypt(algorithm, decKey, action.encData);
              assert.equal(Convert.ToHex(dec), Convert.ToHex(action.data));
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

              const exportedData = await crypto.subtle.exportKey(
                action.format,
                importedKey);

              if (action.format === "jwk") {
                assert.deepEqual(exportedData, action.data);
              } else {
                assert.equal(Buffer.from(exportedData as ArrayBuffer).toString("hex"), Buffer.from(action.data as ArrayBuffer).toString("hex"));
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
                assert.equal(Convert.ToHex(signature), Convert.ToHex(action.signature));
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

              const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
              algorithm.name = algorithm.name.toLowerCase();

              // derive bits
              const derivedBits = await crypto.subtle.deriveBits(algorithm, keys.privateKey, action.length);
              assert.equal(Convert.ToHex(derivedBits), Convert.ToHex(action.data));
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

              const algorithm = Object.assign({}, action.algorithm, { public: keys.publicKey }) as any;
              algorithm.name = algorithm.name.toLowerCase();

              // derive key
              const derivedKey = await crypto.subtle.deriveKey(algorithm, keys.privateKey, action.derivedKeyType, true, action.keyUsages);
              const keyData = await crypto.subtle.exportKey(action.format, derivedKey);
              if (action.format === "jwk") {
                assert.deepEqual(keyData, action.keyData);
              } else {
                assert.equal(Convert.ToHex(keyData as ArrayBuffer), Convert.ToHex(action.keyData as ArrayBuffer));
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
              assert.equal(Convert.ToHex(hash), Convert.ToHex(action.hash));
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
