import * as types from "@peculiar/webcrypto-types";
import { Crypto as NodeCrypto } from "@peculiar/webcrypto";
import { Crypto as WebCrypto, setCrypto } from "../../src";

export const nodeCrypto = new NodeCrypto();
const nativeGenerateKey = nodeCrypto.subtle.generateKey;
const nativeExportKey = nodeCrypto.subtle.exportKey;

// asmCrypto doesn't have key generation function and uses native generateKey with RSA-PSS
nodeCrypto.subtle.generateKey = async function (this: types.SubtleCrypto, ...args: any[]) {
  if (args[0]?.name !== "RSA-PSS") {
    throw new Error("Function is broken for test cases");
  }
  return nativeGenerateKey.apply(this, args as any);
} as any;

// asmCrypto doesn't have key generation function and uses native exportKey with RSA-PSS
nodeCrypto.subtle.exportKey = async function (this: types.SubtleCrypto, ...args: any[]) {
  if (!(
    (args[0] === "pkcs8"
      || args[0] === "spki")
    && args[1].algorithm.name === "RSA-PSS"
  )) {
    throw new Error("Function is broken for test cases");
  }
  return nativeExportKey.apply(this, args as any);
} as any;

// break crypto functions
[
  "decrypt", "encrypt",
  "wrapKey", "unwrapKey",
  "sign", "verify",
  "deriveBits", "deriveKey",
  "importKey",
  "digest",
].forEach((o) => {
  (nodeCrypto.subtle as any)[o] = async () => {
    throw new Error("Function is broken for test cases");
  };
});

// set native crypto
setCrypto(nodeCrypto as types.Crypto);

export const webCrypto = new WebCrypto();
