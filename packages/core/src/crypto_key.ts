import * as types from "@peculiar/webcrypto-types";

const KEY_TYPES = ["secret", "private", "public"];

export class BaseCryptoKey implements types.CryptoKey {

  public static create<T extends BaseCryptoKey>(this: new () => T, algorithm: types.KeyAlgorithm, type: types.KeyType, extractable: boolean, usages: types.KeyUsages): T {
    const key = new this();
    key.algorithm = algorithm;
    key.type = type;
    key.extractable = extractable;
    key.usages = usages;

    return key;
  }

  public static isKeyType(data: any): data is types.KeyType {
    return KEY_TYPES.indexOf(data) !== -1;
  }

  public algorithm!: types.KeyAlgorithm;
  public type!: types.KeyType;
  public usages!: types.KeyUsages;
  public extractable!: boolean;

  // @internal
  public get [Symbol.toStringTag]() {
    return "CryptoKey";
  }
}
