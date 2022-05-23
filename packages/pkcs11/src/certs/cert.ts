import * as graphene from "graphene-pk11";
import * as types from "@peculiar/webcrypto-types";

import { Crypto } from "../crypto";
import { CryptoKey } from "../key";
import { Pkcs11Object } from "../p11_object";
import { Pkcs11Params } from "../types";

export interface Pkcs11CryptoCertificate extends CryptoCertificate {
  token: boolean;
  sensitive: boolean;
  label: string;
}

export type Pkcs11ImportAlgorithms = types.ImportAlgorithms & Pkcs11Params;

export abstract class CryptoCertificate extends Pkcs11Object implements Pkcs11CryptoCertificate {
  public crypto: Crypto;

  public static getID(p11Object: graphene.Storage) {
    let type: string | undefined;
    let id: Buffer | undefined;
    if (p11Object instanceof graphene.Data) {
      type = "request";
      id = p11Object.objectId;
    } else if (p11Object instanceof graphene.X509Certificate) {
      type = "x509";
      id = p11Object.id;
    }
    if (!type || !id) {
      throw new Error("Unsupported PKCS#11 object");
    }
    return `${type}-${p11Object.handle.toString("hex")}-${id.toString("hex")}`;
  }

  public get id() {
    Pkcs11Object.assertStorage(this.p11Object);

    return CryptoCertificate.getID(this.p11Object);
  }

  public type: types.CryptoCertificateType = "x509";
  public publicKey!: CryptoKey;

  public get token() {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.token;
    } catch { /* nothing */ }
    return false;
  }

  public get sensitive() {
    return false;
  }

  public get label() {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.label;
    } catch { /* nothing */ }
    return "";
  }

  public constructor(crypto: Crypto) {
    super();
    this.crypto = crypto;
  }

  public abstract importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: string[]): Promise<void>;
  public abstract exportCert(): Promise<ArrayBuffer>;
  public abstract exportKey(): Promise<CryptoKey>;
  public abstract exportKey(algorithm: types.Algorithm, usages: types.KeyUsage[]): Promise<CryptoKey>;

}
