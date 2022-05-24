import * as types from "@peculiar/webcrypto-types";

declare const self: any;

let window: any = {};
if (typeof self !== "undefined") {
  window = self;
}

export let nativeCrypto: types.Crypto =
  window["msCrypto"]  // IE
  || window.crypto          // other browsers
  || {};                    // if crypto is empty
export let nativeSubtle: types.SubtleCrypto | null = null;
try {
  nativeSubtle = nativeCrypto?.subtle || (nativeCrypto as any)?.["webkitSubtle"] || null;
} catch (err) {
  console.warn("Cannot get subtle from crypto", err);
  // Safari throws error on crypto.webkitSubtle in Worker
}

export function setCrypto(crypto: types.Crypto) {
  nativeCrypto = crypto;
  nativeSubtle = crypto.subtle;
}
