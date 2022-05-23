//#region WebCrypto API

export type BufferSource = ArrayBuffer | ArrayBufferView;

export type KeyFormat = "jwk" | "pkcs8" | "raw" | "spki";

export type KeyType = "private" | "public" | "secret";

export type KeyUsage = "decrypt" | "deriveBits" | "deriveKey" | "encrypt" | "sign" | "unwrapKey" | "verify" | "wrapKey";

export interface Algorithm {
  name: string;
}

export interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: RsaOtherPrimesInfo[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  y?: string;
}

export interface KeyAlgorithm {
  name: string;
}

export type BigInteger = Uint8Array;

export type HashAlgorithmIdentifier = AlgorithmIdentifier;

export type AlgorithmIdentifier = Algorithm | string;

//#region RSA

export interface RsaHashedImportParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
}

export interface RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
  hash: KeyAlgorithm;
}

export interface RsaHashedKeyGenParams extends RsaKeyGenParams {
  hash: HashAlgorithmIdentifier;
}

export interface RsaKeyAlgorithm extends KeyAlgorithm {
  modulusLength: number;
  publicExponent: BigInteger;
}

export interface RsaKeyGenParams extends Algorithm {
  modulusLength: number;
  publicExponent: BigInteger;
}

export interface RsaOaepParams extends Algorithm {
  label?: BufferSource;
}

export interface RsaOtherPrimesInfo {
  d?: string;
  r?: string;
  t?: string;
}

export interface RsaPssParams extends Algorithm {
  saltLength: number;
}

//#endregion

//#region AES

export interface AesCbcParams extends Algorithm {
  iv: BufferSource;
}

export interface AesCtrParams extends Algorithm {
  counter: BufferSource;
  length: number;
}

export interface AesDerivedKeyParams extends Algorithm {
  length: number;
}

export interface AesGcmParams extends Algorithm {
  additionalData?: BufferSource;
  iv: BufferSource;
  tagLength?: number;
}

export interface AesKeyAlgorithm extends KeyAlgorithm {
  length: number;
}

export interface AesKeyGenParams extends Algorithm {
  length: number;
}

//#endregion

//#region EC

export type NamedCurve = string;

export interface EcKeyAlgorithm extends KeyAlgorithm {
  namedCurve: NamedCurve;
}

export interface EcKeyGenParams extends Algorithm {
  namedCurve: NamedCurve;
}

export interface EcKeyImportParams extends Algorithm {
  namedCurve: NamedCurve;
}

export interface EcdhKeyDeriveParams extends Algorithm {
  public: CryptoKey;
}

export interface EcdsaParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
}

//#endregion

//#region HKDF

export interface HkdfParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  info: BufferSource;
  salt: BufferSource;
}

//#endregion

//#region HMAC

export interface HmacImportParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  length?: number;
}

export interface HmacKeyAlgorithm extends KeyAlgorithm {
  hash: KeyAlgorithm;
  length: number;
}

export interface HmacKeyGenParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  length?: number;
}

//#endregion

//#region PKBKDF2

export interface Pbkdf2Params extends Algorithm {
  hash: HashAlgorithmIdentifier;
  iterations: number;
  salt: BufferSource;
}

//#endregion

export interface CryptoKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * The CryptoKey dictionary of the Web Crypto API represents a cryptographic key.
 * Available only in secure contexts.
 */
export interface CryptoKey {
  readonly algorithm: KeyAlgorithm;
  readonly extractable: boolean;
  readonly type: KeyType;
  readonly usages: KeyUsage[];
}

/**
 * This Web Crypto API export interface provides a number of low-level cryptographic functions.
 * It is accessed via the Crypto.subtle properties available in a window context (via Window.crypto).
 *
 * Available only in secure contexts.
 */
export interface SubtleCrypto {
  decrypt(algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams, key: CryptoKey, data: BufferSource): Promise<any>;
  deriveBits(algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;
  deriveKey(algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params, baseKey: CryptoKey, derivedKey: AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams | HkdfParams | Pbkdf2Params, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer>;
  encrypt(algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams, key: CryptoKey, data: BufferSource): Promise<any>;
  exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
  exportKey(format: Exclude<KeyFormat, "jwk">, key: CryptoKey): Promise<ArrayBuffer>;
  exportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey>;
  generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair>;
  generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey>;
  importKey(format: "jwk", keyData: JsonWebKey, algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  importKey(format: Exclude<KeyFormat, "jwk">, keyData: BufferSource, algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  importKey(format: KeyFormat, keyData: BufferSource | JsonWebKey, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  sign(algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer>;
  unwrapKey(format: KeyFormat, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams, unwrappedKeyAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  verify(algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams, key: CryptoKey, signature: BufferSource, data: BufferSource): Promise<boolean>;
  wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams): Promise<ArrayBuffer>;
}

/**
 * Basic cryptography features available in the current context. It allows access to a cryptographically
 * strong random number generator and to cryptographic primitives.
 */
export interface Crypto {
  /**
   * Returns a SubtleCrypto object providing access to common cryptographic primitives,
   * like hashing, signing, encryption or decryption
   *
   * Available only in secure contexts.
   */
  readonly subtle: SubtleCrypto;

  /**
   * Generates cryptographically random values
   * @param array Is an integer-based BufferSource.
   * All elements in the array are going to be overridden with random numbers.
   */
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;

  /**
   * Generates a v4 UUID using a cryptographically secure random number generator
   *
   * Available only in secure contexts.
   * @returns UUID v4 string
   */
  randomUUID(): string;
}

//#endregion

export type HexString = string;
export type KeyUsages = KeyUsage[];

export type ProviderKeyUsage = KeyUsages;

export interface ProviderKeyPairUsage {
  privateKey: KeyUsages;
  publicKey: KeyUsages;
}

export type ProviderKeyUsages = ProviderKeyUsage | ProviderKeyPairUsage;

export interface HashedAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
}

export type ImportAlgorithms = Algorithm | RsaHashedImportParams | EcKeyImportParams;

/**
 * Base generic class for crypto storages
 */
export interface CryptoStorage<T> {
  /**
   * Returns list of indexes from storage
   */
  keys(): Promise<string[]>;

  /**
   * Returns index of item in storage
   * @param item Crypto item
   * @returns Index of item in storage otherwise null
   */
  indexOf(item: T): Promise<string | null>;

  /**
   * Add crypto item to storage and returns it's index
   */
  setItem(item: T): Promise<string>;

  /**
   * Returns crypto item from storage by index
   * @param index index of crypto item
   * @returns Crypto item
   * @throws Throws Error when cannot find crypto item in storage
   */
  getItem(index: string): Promise<T>;

  /**
   * Returns `true` if item is in storage otherwise `false`
   * @param item Crypto item
   */
  hasItem(item: T): Promise<boolean>;

  /**
   * Removes all items from storage
   */
  clear(): Promise<void>;

  /**
   * Removes crypto item from storage by index
   * @param index Index of crypto storage
   */
  removeItem(index: string): Promise<void>;

}

//#region CryptoKeyStorage

export interface CryptoKeyStorage extends CryptoStorage<CryptoKey> {

  getItem(index: string): Promise<CryptoKey>;
  getItem(index: string, algorithm: ImportAlgorithms, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;

}

//#endregion CryptoKeyStorage

//#region CryptoCertificateStorage

export type CryptoCertificateFormat = "raw" | "pem";
export type CryptoCertificateType = "x509" | "request";

export interface CryptoCertificate {
  type: CryptoCertificateType;
  publicKey: CryptoKey;
}

export interface CryptoX509Certificate extends CryptoCertificate {
  type: "x509";
  notBefore: Date;
  notAfter: Date;
  serialNumber: HexString;
  issuerName: string;
  subjectName: string;
}

export interface CryptoX509CertificateRequest extends CryptoCertificate {
  type: "request";
  subjectName: string;
}

export interface CryptoCertificateStorage extends CryptoStorage<CryptoCertificate> {

  getItem(index: string): Promise<CryptoCertificate>;
  getItem(index: string, algorithm: ImportAlgorithms, keyUsages: KeyUsage[]): Promise<CryptoCertificate>;

  exportCert(format: CryptoCertificateFormat, item: CryptoCertificate): Promise<ArrayBuffer | string>;
  exportCert(format: "raw", item: CryptoCertificate): Promise<ArrayBuffer>;
  exportCert(format: "pem", item: CryptoCertificate): Promise<string>;

  importCert(format: CryptoCertificateFormat, data: BufferSource | string, algorithm: ImportAlgorithms, keyUsages: KeyUsage[]): Promise<CryptoCertificate>;
  importCert(format: "raw", data: BufferSource, algorithm: ImportAlgorithms, keyUsages: KeyUsage[]): Promise<CryptoCertificate>;
  importCert(format: "pem", data: string, algorithm: ImportAlgorithms, keyUsages: KeyUsage[]): Promise<CryptoCertificate>;
}

//#endregion CryptoCertificateStorage

export interface CryptoStorages {
  keyStorage: CryptoKeyStorage;
  certStorage: CryptoCertificateStorage;
}

export type PreparedHashedAlgorithm<T extends Algorithm = Algorithm> = Omit<T, "hash"> & { hash: Algorithm; };

export interface AesCmacParams extends Algorithm {
  length: number;
}
