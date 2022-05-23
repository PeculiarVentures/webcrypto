import * as types from "@peculiar/webcrypto-types";

export interface ITestAction {
  name?: string;
  only?: boolean;
  skip?: boolean;
  error?: any;
}

export interface ITestVectorsExclude {
  [name: string]: boolean | undefined;
  AES128CBC?: boolean;
  AES192CBC?: boolean;
  AES256CBC?: boolean;
  AES128CMAC?: boolean;
  AES192CMAC?: boolean;
  AES128CTR?: boolean;
  AES192CTR?: boolean;
  AES256CTR?: boolean;
  AES128ECB?: boolean;
  AES192ECB?: boolean;
  AES256ECB?: boolean;
  AES128GCM?: boolean;
  AES192GCM?: boolean;
  AES256GCM?: boolean;
  AES128KW?: boolean;
  AES192KW?: boolean;
  AES256KW?: boolean;

  DESCBC?: boolean;
  DESEDE3CBC?: boolean;

  RSAESPKCS1?: boolean;
  RSASSAPKCS1?: boolean;
  RSAOAEP?: boolean;
  RSAPSS?: boolean;

  ECDSA?: boolean;
  ECDH?: boolean;

  HKDF?: boolean;
  HMAC?: boolean;
  PBKDF2?: boolean;
  SHA?: boolean;
}

export interface ITestGenerateKeyAction extends ITestAction {
  algorithm: types.Algorithm;
  extractable: boolean;
  keyUsages: types.KeyUsage[];
  assert?: (keys: types.CryptoKey | types.CryptoKeyPair) => void;
}

export interface IImportKeyParams {
  format: types.KeyFormat;
  data: types.JsonWebKey | types.BufferSource;
  algorithm: types.AlgorithmIdentifier;
  extractable: boolean;
  keyUsages: types.KeyUsage[];
  assert?: (keys: types.CryptoKey) => void;
}

export interface IImportKeyPairParams {
  privateKey: IImportKeyParams;
  publicKey: IImportKeyParams;
}

export interface ITestEncryptAction extends ITestAction {
  algorithm: types.Algorithm;
  data: types.BufferSource;
  encData: types.BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestSignAction extends ITestAction {
  algorithm: types.Algorithm;
  data: types.BufferSource;
  signature: types.BufferSource;
  key: IImportKeyParams | IImportKeyPairParams;
}

export interface ITestDeriveBitsAction extends ITestAction {
  algorithm: types.Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  data: types.BufferSource;
  length: number;
}

export interface ITestDeriveKeyAction extends ITestAction {
  algorithm: types.Algorithm;
  key: IImportKeyParams | IImportKeyPairParams;
  derivedKeyType: types.Algorithm;
  keyUsages: types.KeyUsage[];
  format: types.KeyFormat;
  keyData: types.BufferSource | types.JsonWebKey;
  assert?: (keys: types.CryptoKey) => void;
}

export interface ITestWrapKeyAction extends ITestAction {
  key: IImportKeyParams | IImportKeyPairParams;
  algorithm: types.Algorithm;
  wKey: IImportKeyParams;
  wrappedKey?: types.BufferSource;
}

export interface ITestImportAction extends IImportKeyParams, ITestAction {
}

export interface ITestDigestAction extends ITestAction {
  algorithm: types.AlgorithmIdentifier;
  data: types.BufferSource;
  hash: types.BufferSource;
}

export interface ITestActions {
  generateKey?: ITestGenerateKeyAction[];
  encrypt?: ITestEncryptAction[];
  wrapKey?: ITestWrapKeyAction[];
  sign?: ITestSignAction[];
  import?: ITestImportAction[];
  deriveBits?: ITestDeriveBitsAction[];
  deriveKey?: ITestDeriveKeyAction[];
  digest?: ITestDigestAction[];
}

export interface ITestParams {
  name: string;
  only?: boolean;
  actions: ITestActions;
}
