import * as types from "@peculiar/webcrypto-types";
import { BufferSource, BufferSourceConverter, Convert } from "pvtsutils";
import { AlgorithmError } from "./errors";
import { ProviderCrypto } from "./provider";
import { ProviderStorage } from "./storage";
import { CryptoKey } from './crypto_key';

export class SubtleCrypto implements types.SubtleCrypto {

  public static isHashedAlgorithm(data: any): data is types.HashedAlgorithm {
    return data
      && typeof data === "object"
      && "name" in data
      && "hash" in data
      ? true
      : false;
  }

  public providers = new ProviderStorage();

  // @internal
  public get [Symbol.toStringTag]() {
    return "SubtleCrypto";
  }

  public async digest(algorithm: types.AlgorithmIdentifier, data: BufferSource, ...args: any[]): Promise<ArrayBuffer>;
  public async digest(...args: any[]): Promise<ArrayBuffer> {
    this.checkRequiredArguments(args, 2, "digest");
    const [algorithm, data, ...params] = args;

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(data);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.digest(preparedAlgorithm, preparedData, ...params);

    return result;
  }

  public async generateKey(algorithm: types.RsaHashedKeyGenParams | types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKeyPair>;
  public async generateKey(algorithm: types.AesKeyGenParams | types.HmacKeyGenParams | types.Pbkdf2Params, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey>;
  public async generateKey(algorithm: types.AlgorithmIdentifier, extractable: boolean, keyUsages: Iterable<types.KeyUsage>, ...args: any[]): Promise<types.CryptoKeyPair | types.CryptoKey>;
  public async generateKey(...args: any[]): Promise<types.CryptoKeyPair | types.CryptoKey> {
    this.checkRequiredArguments(args, 3, "generateKey");
    const [algorithm, extractable, keyUsages, ...params] = args;

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.generateKey({ ...preparedAlgorithm, name: provider.name }, extractable, keyUsages, ...params);

    return result;
  }

  public async sign(algorithm: types.AlgorithmIdentifier, key: types.CryptoKey, data: BufferSource, ...args: any[]): Promise<ArrayBuffer>;
  public async sign(...args: any[]): Promise<ArrayBuffer> {
    this.checkRequiredArguments(args, 3, "sign");
    const [algorithm, key, data, ...params] = args;
    this.checkCryptoKey(key);

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(data);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.sign({ ...preparedAlgorithm, name: provider.name }, key, preparedData, ...params);

    return result;
  }

  public async verify(algorithm: types.AlgorithmIdentifier, key: types.CryptoKey, signature: BufferSource, data: BufferSource, ...args: any[]): Promise<boolean>;
  public async verify(...args: any[]): Promise<boolean> {
    this.checkRequiredArguments(args, 4, "verify");
    const [algorithm, key, signature, data, ...params] = args;
    this.checkCryptoKey(key);

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(data);
    const preparedSignature = BufferSourceConverter.toArrayBuffer(signature);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.verify({ ...preparedAlgorithm, name: provider.name }, key, preparedSignature, preparedData, ...params);

    return result;
  }

  public async encrypt(algorithm: types.AlgorithmIdentifier, key: types.CryptoKey, data: BufferSource, ...args: any[]): Promise<ArrayBuffer>;
  public async encrypt(...args: any[]): Promise<ArrayBuffer> {
    this.checkRequiredArguments(args, 3, "encrypt");
    const [algorithm, key, data, ...params] = args;
    this.checkCryptoKey(key);

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(data);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.encrypt({ ...preparedAlgorithm, name: provider.name }, key, preparedData, { keyUsage: true }, ...params);

    return result;
  }

  public async decrypt(algorithm: types.AlgorithmIdentifier, key: types.CryptoKey, data: BufferSource, ...args: any[]): Promise<ArrayBuffer>;
  public async decrypt(...args: any[]): Promise<ArrayBuffer> {
    this.checkRequiredArguments(args, 3, "decrypt");
    const [algorithm, key, data, ...params] = args;
    this.checkCryptoKey(key);

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(data);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.decrypt({ ...preparedAlgorithm, name: provider.name }, key, preparedData, { keyUsage: true }, ...params);

    return result;
  }

  public async deriveBits(algorithm: types.AlgorithmIdentifier, baseKey: types.CryptoKey, length: number, ...args: any[]): Promise<ArrayBuffer>;
  public async deriveBits(...args: any[]): Promise<ArrayBuffer> {
    this.checkRequiredArguments(args, 3, "deriveBits");
    const [algorithm, baseKey, length, ...params] = args;
    this.checkCryptoKey(baseKey);

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);

    const provider = this.getProvider(preparedAlgorithm.name);
    const result = await provider.deriveBits({ ...preparedAlgorithm, name: provider.name }, baseKey, length, { keyUsage: true }, ...params);

    return result;
  }

  public async deriveKey(algorithm: types.AlgorithmIdentifier, baseKey: types.CryptoKey, derivedKeyType: types.AlgorithmIdentifier, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey>;
  public async deriveKey(...args: any[]): Promise<types.CryptoKey> {
    this.checkRequiredArguments(args, 5, "deriveKey");
    const [algorithm, baseKey, derivedKeyType, extractable, keyUsages, ...params] = args;
    // check derivedKeyType
    const preparedDerivedKeyType = this.prepareAlgorithm(derivedKeyType);
    const importProvider = this.getProvider(preparedDerivedKeyType.name);
    importProvider.checkDerivedKeyParams(preparedDerivedKeyType);

    // derive bits
    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const provider = this.getProvider(preparedAlgorithm.name);
    provider.checkCryptoKey(baseKey, "deriveKey");
    const derivedBits = await provider.deriveBits({ ...preparedAlgorithm, name: provider.name }, baseKey, (derivedKeyType as any).length || 512, { keyUsage: false }, ...params);

    // import derived key
    return this.importKey("raw", derivedBits, derivedKeyType, extractable, keyUsages, ...params);
  }

  public async exportKey(format: "raw" | "spki" | "pkcs8", key: types.CryptoKey, ...args: any[]): Promise<ArrayBuffer>;
  public async exportKey(format: "jwk", key: types.CryptoKey, ...args: any[]): Promise<types.JsonWebKey>;
  public async exportKey(format: types.KeyFormat, key: types.CryptoKey, ...args: any[]): Promise<types.JsonWebKey | ArrayBuffer>;
  public async exportKey(...args: any[]): Promise<types.JsonWebKey | ArrayBuffer> {
    this.checkRequiredArguments(args, 2, "exportKey");
    const [format, key, ...params] = args;
    this.checkCryptoKey(key);

    const provider = this.getProvider(key.algorithm.name);
    const result = await provider.exportKey(format, key, ...params);

    return result;
  }
  public async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | BufferSource, algorithm: types.AlgorithmIdentifier, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey>;
  public async importKey(...args: any[]): Promise<types.CryptoKey> {
    this.checkRequiredArguments(args, 5, "importKey");
    const [format, keyData, algorithm, extractable, keyUsages, ...params] = args;

    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const provider = this.getProvider(preparedAlgorithm.name);

    if (["pkcs8", "spki", "raw"].indexOf(format) !== -1) {
      const preparedData = BufferSourceConverter.toArrayBuffer(keyData as BufferSource);

      return provider.importKey(format, preparedData, { ...preparedAlgorithm, name: provider.name }, extractable, keyUsages, ...params);
    } else {
      if (!(keyData as types.JsonWebKey).kty) {
        throw new TypeError("keyData: Is not JSON");
      }
    }
    return provider.importKey(format, keyData as types.JsonWebKey, { ...preparedAlgorithm, name: provider.name }, extractable, keyUsages, ...params);
  }

  public async wrapKey(format: types.KeyFormat, key: types.CryptoKey, wrappingKey: types.CryptoKey, wrapAlgorithm: types.AlgorithmIdentifier, ...args: any[]): Promise<ArrayBuffer> {
    let keyData = await this.exportKey(format, key, ...args);
    if (format === "jwk") {
      const json = JSON.stringify(keyData);
      keyData = Convert.FromUtf8String(json);
    }

    // encrypt key data
    const preparedAlgorithm = this.prepareAlgorithm(wrapAlgorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(keyData as ArrayBuffer);
    const provider = this.getProvider(preparedAlgorithm.name);
    return provider.encrypt({ ...preparedAlgorithm, name: provider.name }, wrappingKey, preparedData, { keyUsage: false }, ...args);
  }

  public async unwrapKey(format: types.KeyFormat, wrappedKey: BufferSource, unwrappingKey: types.CryptoKey, unwrapAlgorithm: types.AlgorithmIdentifier, unwrappedKeyAlgorithm: types.AlgorithmIdentifier, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<types.CryptoKey> {
    // decrypt wrapped key
    const preparedAlgorithm = this.prepareAlgorithm(unwrapAlgorithm);
    const preparedData = BufferSourceConverter.toArrayBuffer(wrappedKey);
    const provider = this.getProvider(preparedAlgorithm.name);
    let keyData = await provider.decrypt({ ...preparedAlgorithm, name: provider.name }, unwrappingKey, preparedData, { keyUsage: false }, ...args);
    if (format === "jwk") {
      try {
        keyData = JSON.parse(Convert.ToUtf8String(keyData));
      } catch (e) {
        const error = new TypeError("wrappedKey: Is not a JSON");
        (error as any).internal = e;
        throw error;
      }
    }

    // import key
    return this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages, ...args);
  }

  protected checkRequiredArguments(args: any[], size: number, methodName: string) {
    if (args.length < size) {
      throw new TypeError(`Failed to execute '${methodName}' on 'SubtleCrypto': ${size} arguments required, but only ${args.length} present`);
    }
  }

  protected prepareAlgorithm(algorithm: types.AlgorithmIdentifier): types.Algorithm | types.HashedAlgorithm {
    if (typeof algorithm === "string") {
      return {
        name: algorithm,
      } as types.Algorithm;
    }
    if (SubtleCrypto.isHashedAlgorithm(algorithm)) {
      const preparedAlgorithm = { ...algorithm };
      preparedAlgorithm.hash = this.prepareAlgorithm(algorithm.hash);
      return preparedAlgorithm as types.HashedAlgorithm;
    }
    return { ...algorithm };
  }

  protected getProvider(name: string): ProviderCrypto {
    const provider = this.providers.get(name);
    if (!provider) {
      throw new AlgorithmError("Unrecognized name");
    }
    return provider;
  }

  protected checkCryptoKey(key: types.CryptoKey): asserts key is CryptoKey {
    if (!(key instanceof CryptoKey)) {
      throw new TypeError(`Key is not of type 'CryptoKey'`);
    }
  }

}
