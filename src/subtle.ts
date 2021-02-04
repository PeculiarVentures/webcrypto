import * as process from "process";
import * as core from "webcrypto-core";
import {
  AesCbcProvider, AesCmacProvider, AesCtrProvider, AesEcbProvider, AesGcmProvider, AesKwProvider,
  DesCbcProvider,
  DesEde3CbcProvider, EcdhProvider,
  EcdsaProvider, HkdfProvider,
  EdDsaProvider,
  EcdhEsProvider,
  HmacProvider,
  Pbkdf2Provider,
  RsaEsProvider, RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha384Provider, Sha512Provider,
} from "./mechs";

export class SubtleCrypto extends core.SubtleCrypto {
  constructor() {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider());
    this.providers.set(new AesCtrProvider());
    this.providers.set(new AesGcmProvider());
    this.providers.set(new AesCmacProvider());
    this.providers.set(new AesKwProvider());
    this.providers.set(new AesEcbProvider());
    //#endregion

    //#region DES
    this.providers.set(new DesCbcProvider());
    this.providers.set(new DesEde3CbcProvider());
    //#endregion

    //#region RSA
    this.providers.set(new RsaSsaProvider());
    this.providers.set(new RsaPssProvider());
    this.providers.set(new RsaOaepProvider());
    this.providers.set(new RsaEsProvider());
    //#endregion

    //#region EC
    this.providers.set(new EcdsaProvider());
    this.providers.set(new EcdhProvider());
    //#endregion

    //#region SHA
    this.providers.set(new Sha1Provider());
    this.providers.set(new Sha256Provider());
    this.providers.set(new Sha384Provider());
    this.providers.set(new Sha512Provider());
    //#endregion

    //#region PBKDF
    this.providers.set(new Pbkdf2Provider());
    //#endregion

    //#region HMAC
    this.providers.set(new HmacProvider());
    //#endregion

    //#region HKDF
    this.providers.set(new HkdfProvider());
    //#endregion

    const nodeMajorVersion = /^v(\d+)/.exec(process.version)?.[1];
    if (nodeMajorVersion && parseInt(nodeMajorVersion, 10) >= 14) {
      //#region EdDSA
      this.providers.set(new EdDsaProvider());
      //#endregion

      //#region ECDH-ES
      this.providers.set(new EcdhEsProvider());
      //#endregion
    }
  }
}
