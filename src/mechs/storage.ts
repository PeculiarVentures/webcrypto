import * as core from "webcrypto-core";
import { CryptoKey as InternalCryptoKey } from "../keys";

const keyStorage = new WeakMap<core.CryptoKey, InternalCryptoKey>();

export function getCryptoKey(key: core.CryptoKey) {
  const res = keyStorage.get(key);
  if (!res) {
    throw new core.OperationError("Cannot get CryptoKey from secure storage");
  }
  return res;
}

export function setCryptoKey(value: InternalCryptoKey) {
  const key = core.CryptoKey.create(value.algorithm, value.type, value.extractable, value.usages);
  Object.freeze(key);

  keyStorage.set(key, value);

  return key;
}
