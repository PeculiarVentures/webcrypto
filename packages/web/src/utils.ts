import * as types from "@peculiar/webcrypto-types";

export function isAlgorithm<T extends types.Algorithm>(algorithm: types.Algorithm, name: string): algorithm is T {
  return algorithm.name.toUpperCase() === name.toUpperCase();
}
