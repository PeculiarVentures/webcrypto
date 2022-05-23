import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { CryptoKey as InternalCryptoKey } from "../keys";

const keyStorage = new WeakMap<types.CryptoKey, InternalCryptoKey>();

export function getCryptoKey(key: types.CryptoKey) {

  const res = keyStorage.get(key);
  if (!res) {
    throw new core.OperationError("Cannot get CryptoKey from secure storage");
  }
  return res;
}

export function setCryptoKey(value: InternalCryptoKey) {
  const key = core.BaseCryptoKey.create(value.algorithm, value.type, value.extractable, value.usages);
  Object.freeze(key);

  keyStorage.set(key, value);

  return key;
}
