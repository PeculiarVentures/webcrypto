// Core
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { KeyType } from "crypto";
import * as graphene from "graphene-pk11";

import { Pkcs11KeyAlgorithm } from "./types";

export interface ITemplatePair {
  privateKey: graphene.ITemplate;
  publicKey: graphene.ITemplate;
}

export class CryptoKey<T extends Pkcs11KeyAlgorithm = Pkcs11KeyAlgorithm> extends core.CryptoKey {

  public static defaultKeyAlgorithm() {
    const alg: Pkcs11KeyAlgorithm = {
      label: "",
      name: "",
      sensitive: false,
      token: false,
    };
    return alg;
  }

  public static getID(p11Key: graphene.Key) {
    let name: string;
    switch (p11Key.class) {
      case graphene.ObjectClass.PRIVATE_KEY:
        name = "private";
        break;
      case graphene.ObjectClass.PUBLIC_KEY:
        name = "public";
        break;
      case graphene.ObjectClass.SECRET_KEY:
        name = "secret";
        break;
      default:
        throw new Error(`Unsupported Object type '${graphene.ObjectClass[p11Key.class]}'`);
    }
    return `${name}-${p11Key.handle.toString("hex")}-${p11Key.id.toString("hex")}`;
  }

  public id: string;
  public p11Object: graphene.Key | graphene.SecretKey | graphene.PublicKey | graphene.PrivateKey;
  public override algorithm: T;

  public get key(): graphene.Key {
    return this.p11Object.toType<graphene.Key>();
  }

  constructor(key: graphene.Key, alg: T | types.KeyAlgorithm, usages?: types.KeyUsage[]) {
    super();
    this.p11Object = key;
    switch (key.class) {
      case graphene.ObjectClass.PUBLIC_KEY:
        this.initPublicKey(key.toType<graphene.PublicKey>());
        break;
      case graphene.ObjectClass.PRIVATE_KEY:
        this.initPrivateKey(key.toType<graphene.PrivateKey>());
        break;
      case graphene.ObjectClass.SECRET_KEY:
        this.initSecretKey(key.toType<graphene.SecretKey>());
        break;
      default:
        throw new core.CryptoError(`Wrong incoming session object '${graphene.ObjectClass[key.class]}'`);
    }
    const { name, ...defaultAlg } = CryptoKey.defaultKeyAlgorithm();
    this.algorithm = { ...alg, ...defaultAlg } as T;
    this.id = CryptoKey.getID(key);

    if (usages) {
      this.usages = usages;
    }

    try {
      this.algorithm.label = key.label;
    } catch { /*nothing*/ }
    try {
      this.algorithm.token = key.token;
    } catch { /*nothing*/ }
    try {
      if (key instanceof graphene.PrivateKey || key instanceof graphene.SecretKey) {
        this.algorithm.sensitive = key.get("sensitive");
      }
    } catch { /*nothing*/ }

    this.onAssign();
  }

  public toJSON() {
    return {
      algorithm: this.algorithm,
      type: this.type,
      usages: this.usages,
      extractable: this.extractable,
    };
  }

  protected initPrivateKey(key: graphene.PrivateKey) {
    this.p11Object = key;
    this.type = "private";
    try {
      // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
      this.extractable = key.extractable;
    } catch (e) {
      this.extractable = false;
    }
    this.usages = [];
    if (key.decrypt) {
      this.usages.push("decrypt");
    }
    if (key.derive) {
      this.usages.push("deriveKey");
      this.usages.push("deriveBits");
    }
    if (key.sign) {
      this.usages.push("sign");
    }
    if (key.unwrap) {
      this.usages.push("unwrapKey");
    }
  }

  protected initPublicKey(key: graphene.PublicKey) {
    this.p11Object = key;
    this.type = "public";
    this.extractable = true;
    if (key.encrypt) {
      this.usages.push("encrypt");
    }
    if (key.verify) {
      this.usages.push("verify");
    }
    if (key.wrap) {
      this.usages.push("wrapKey");
    }
  }

  protected initSecretKey(key: graphene.SecretKey) {
    this.p11Object = key;
    this.type = "secret";
    try {
      // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
      this.extractable = key.extractable;
    } catch (e) {
      this.extractable = false;
    }
    if (key.sign) {
      this.usages.push("sign");
    }
    if (key.verify) {
      this.usages.push("verify");
    }
    if (key.encrypt) {
      this.usages.push("encrypt");
    }
    if (key.decrypt) {
      this.usages.push("decrypt");
    }
    if (key.wrap) {
      this.usages.push("wrapKey");
    }
    if (key.unwrap) {
      this.usages.push("unwrapKey");
    }
    if (key.derive) {
      this.usages.push("deriveKey");
      this.usages.push("deriveBits");
    }
  }

  protected onAssign() {
    // nothing
  }

}
