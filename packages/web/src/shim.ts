import { Crypto, nativeCrypto } from ".";
import { Debug } from "./debug";
import "./init";

declare const self: any;

const window = self as any;

if (nativeCrypto) {
  Object.freeze(nativeCrypto.getRandomValues);
}

try {
  // Replace original crypto by liner
  delete (self as any).crypto;
  window.crypto = new Crypto();
  Object.freeze(window.crypto);
} catch (e) {
  Debug.error(e);
}

export const crypto = window.crypto;
export * from ".";
