import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";

import * as certs from "./certs";
import { Crypto } from "./crypto";
import { Pkcs11Object } from "./p11_object";

const TEMPLATES = [
  { class: graphene.ObjectClass.CERTIFICATE, certType: graphene.CertificateType.X_509, token: true },
  { class: graphene.ObjectClass.DATA, token: true, label: "X509 Request" },
];

export interface IGetValue {
  /**
   * Returns item blob
   * @param key Object identifier
   */
  getValue(key: string): Promise<ArrayBuffer | null>;
}
export class CertificateStorage implements types.CryptoCertificateStorage, IGetValue {

  protected crypto: Crypto;

  constructor(crypto: Crypto) {
    this.crypto = crypto;
  }

  public async getValue(key: string): Promise<ArrayBuffer | null> {
    const storageObject = this.getItemById(key);
    if (storageObject instanceof graphene.X509Certificate) {
      const x509Object = storageObject.toType<graphene.X509Certificate>();
      const x509 = new certs.X509Certificate(this.crypto);
      x509.p11Object = x509Object;
      return x509.exportCert();
    } else if (storageObject instanceof graphene.Data) {
      const x509Object = storageObject.toType<graphene.Data>();
      const x509request = new certs.X509CertificateRequest(this.crypto);
      x509request.p11Object = x509Object;
      return x509request.exportCert();
    }
    return null;
  }

  public indexOf(item: types.CryptoCertificate): Promise<string | null>;
  public async indexOf(item: certs.CryptoCertificate) {
    if (item instanceof certs.CryptoCertificate && item.p11Object?.token) {
      return certs.CryptoCertificate.getID(item.p11Object);
    }
    return null;
  }

  public async keys() {
    const keys: string[] = [];
    TEMPLATES.forEach((template) => {
      this.crypto.session!.find(template, (obj) => {
        const item = obj.toType<any>();
        const id = certs.CryptoCertificate.getID(item);
        keys.push(id);
      });
    });
    return keys;
  }

  public async clear() {
    const objects: graphene.SessionObject[] = [];
    TEMPLATES.forEach((template) => {
      this.crypto.session!.find(template, (obj) => {
        objects.push(obj);
      });
    });
    objects.forEach((obj) => {
      obj.destroy();
    });
  }

  public async hasItem(item: types.CryptoCertificate) {
    if (!(item instanceof certs.CryptoCertificate)) {
      throw new TypeError(`Parameter 'item' is not of type 'CryptoCertificate'`);
    }

    const sessionObject = this.getItemById(item.id);

    return !!sessionObject;
  }

  public getItem(index: string): Promise<types.CryptoCertificate>;
  public getItem(index: string, algorithm: types.ImportAlgorithms, keyUsages: types.KeyUsage[]): Promise<types.CryptoCertificate>;
  public async getItem(index: string, algorithm?: types.Algorithm, usages?: types.KeyUsage[]): Promise<types.CryptoCertificate> {
    const storageObject = this.getItemById(index);
    if (storageObject instanceof graphene.X509Certificate) {
      const x509Object = storageObject.toType<graphene.X509Certificate>();
      const x509 = new certs.X509Certificate(this.crypto);
      x509.p11Object = x509Object;
      if (algorithm && usages) {
        await x509.exportKey(algorithm, usages);
      } else {
        await x509.exportKey();
      }
      return x509;
    } else if (storageObject instanceof graphene.Data) {
      const x509Object = storageObject.toType<graphene.Data>();
      const x509request = new certs.X509CertificateRequest(this.crypto);
      x509request.p11Object = x509Object;
      if (algorithm && usages) {
        await x509request.exportKey(algorithm, usages);
      } else {
        await x509request.exportKey();
      }
      return x509request;
    } else {
      // @ts-ignore
      return null;
    }
  }

  public async removeItem(key: string) {
    const sessionObject = this.getItemById(key);
    if (sessionObject) {
      sessionObject.destroy();
    }
  }

  public async setItem(data: types.CryptoCertificate): Promise<string>;
  public async setItem(data: certs.CryptoCertificate) {
    if (!(data instanceof certs.CryptoCertificate)) {
      throw new Error("Incoming data is not PKCS#11 CryptoCertificate");
    }
    Pkcs11Object.assertStorage(data.p11Object);

    // don't copy object from token
    if (!data.p11Object.token) {
      const template = this.crypto.templateBuilder.build({
        action: "copy",
        type: data.type,
        attributes: {
          token: true,
        }
      });
      const obj = this.crypto.session.copy(data.p11Object, template);
      return certs.CryptoCertificate.getID(obj.toType<any>());
    } else {
      return data.id;
    }
  }

  public exportCert(format: types.CryptoCertificateFormat, item: types.CryptoCertificate): Promise<ArrayBuffer | string>;
  public exportCert(format: "raw", item: types.CryptoCertificate): Promise<ArrayBuffer>;
  public exportCert(format: "pem", item: types.CryptoCertificate): Promise<string>;
  public async exportCert(format: types.CryptoCertificateFormat, cert: certs.CryptoCertificate): Promise<ArrayBuffer | string> {
    switch (format) {
      case "pem": {
        throw Error("PEM format is not implemented");
      }
      case "raw": {
        return cert.exportCert();
      }
      default:
        throw new Error(`Unsupported format in use ${format}`);
    }
  }

  public async importCert(format: types.CryptoCertificateFormat, data: types.BufferSource | string, algorithm: certs.Pkcs11ImportAlgorithms, keyUsages: types.KeyUsage[]): Promise<types.CryptoCertificate>;
  public async importCert(format: "raw", data: types.BufferSource, algorithm: certs.Pkcs11ImportAlgorithms, keyUsages: types.KeyUsage[]): Promise<types.CryptoCertificate>;
  public async importCert(format: "pem", data: string, algorithm: certs.Pkcs11ImportAlgorithms, keyUsages: types.KeyUsage[]): Promise<types.CryptoCertificate>;
  public async importCert(format: types.CryptoCertificateFormat, data: types.BufferSource | string, algorithm: certs.Pkcs11ImportAlgorithms, usages: types.KeyUsage[]): Promise<certs.CryptoCertificate> {
    let rawData: ArrayBuffer;
    let rawType: types.CryptoCertificateType | null = null;

    //#region Check
    switch (format) {
      case "pem":
        if (typeof data !== "string") {
          throw new TypeError("data: Is not type string");
        }
        if (core.PemConverter.isCertificate(data)) {
          rawType = "x509";
        } else if (core.PemConverter.isCertificateRequest(data)) {
          rawType = "request";
        } else {
          throw new core.OperationError("data: Is not correct PEM data. Must be Certificate or Certificate Request");
        }
        rawData = core.PemConverter.toArrayBuffer(data);
        break;
      case "raw":
        if (!pvtsutils.BufferSourceConverter.isBufferSource(data)) {
          throw new TypeError("data: Is not type ArrayBuffer or ArrayBufferView");
        }
        rawData = pvtsutils.BufferSourceConverter.toArrayBuffer(data);
        break;
      default:
        throw new TypeError("format: Is invalid value. Must be 'raw', 'pem'");
    }
    //#endregion
    switch (rawType) {
      case "x509": {
        const x509 = new certs.X509Certificate(this.crypto);
        await x509.importCert(Buffer.from(rawData), algorithm, usages);
        return x509;
      }
      case "request": {
        const request = new certs.X509CertificateRequest(this.crypto);
        await request.importCert(Buffer.from(rawData), algorithm, usages);
        return request;
      }
      default: {
        try {
          const x509 = new certs.X509Certificate(this.crypto);
          await x509.importCert(Buffer.from(rawData), algorithm, usages);
          return x509;
        } catch {
          // nothing
        }

        try {
          const request = new certs.X509CertificateRequest(this.crypto);
          await request.importCert(Buffer.from(rawData), algorithm, usages);
          return request;
        } catch {
          // nothing
        }

        throw new core.OperationError("Cannot parse Certificate or Certificate Request from incoming ASN1");
      }
    }
  }

  protected getItemById(id: string): graphene.SessionObject | null {

    let object: graphene.SessionObject | null = null;
    TEMPLATES.forEach((template) => {
      this.crypto.session!.find(template, (obj) => {
        const item = obj.toType<any>();
        if (id === certs.CryptoCertificate.getID(item)) {
          object = item;
          return false;
        }
      });
    });
    return object;
  }

}
