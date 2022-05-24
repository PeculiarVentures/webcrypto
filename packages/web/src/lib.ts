import { Crypto, nativeCrypto } from ".";
import "./init";

if (nativeCrypto) {
    Object.freeze(nativeCrypto.getRandomValues);
}

export const crypto = new Crypto();
export * from ".";
