import * as core from "webcrypto-core";

export declare class Crypto implements core.NativeCrypto {
  public subtle: SubtleCrypto;
  public getRandomValues<T extends Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null>(array: T): T;
}

export declare class CryptoKey implements core.NativeCryptoKey {
  public algorithm: KeyAlgorithm;
  public extractable: boolean;
  public type: KeyType;
  public usages: KeyUsage[];
}
