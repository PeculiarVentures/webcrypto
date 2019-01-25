type NativeCrypto = Crypto;
type NativeSubtleCrypto = SubtleCrypto;
type NativeCryptoKey = CryptoKey;

declare namespace WebCrypto {

  class Crypto implements NativeCrypto {
    public subtle: SubtleCrypto;
    public getRandomValues<T extends Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null>(array: T): T;
  }

  class CryptoKey implements NativeCryptoKey {
    public algorithm: KeyAlgorithm;
    public extractable: boolean;
    public type: KeyType;
    public usages: KeyUsage[];
  }

}

export = WebCrypto;
