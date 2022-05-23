import { CryptoKey } from "../src";
import { config } from "./config";

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

function testManufacturer(manufacturerID: string, message: string) {
  if (config.name === manufacturerID) {
    console.warn("    \x1b[33mWARN:\x1b[0m Test is not supported for %s. %s", manufacturerID, message || "");
    return true;
  }
  return false;
}

export function isSoftHSM(message: string) {
  return testManufacturer("SoftHSMv2", message);
}

export function isNSS(message: string) {
  return testManufacturer("NSS", message);
}
