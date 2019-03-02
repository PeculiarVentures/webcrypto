import * as core from "webcrypto-core";
import {
  AesCbcProvider, AesCtrProvider, AesGcmProvider, AesKwProvider,
  DesCbcProvider, DesEde3CbcProvider,
  EcdhProvider, EcdsaProvider,
  HmacProvider,
  Pbkdf2Provider,
  RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha384Provider, Sha512Provider,
} from "./mechs";

export class SubtleCrypto extends core.SubtleCrypto {
  constructor() {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider());
    this.providers.set(new AesCtrProvider());
    this.providers.set(new AesGcmProvider());
    this.providers.set(new AesKwProvider());
    //#endregion

    //#region DES
    this.providers.set(new DesCbcProvider());
    this.providers.set(new DesEde3CbcProvider());
    //#endregion

    //#region RSA
    this.providers.set(new RsaSsaProvider());
    this.providers.set(new RsaPssProvider());
    // this.providers.set(new RsaOaepProvider()); // TODO: Fix encrypt/decrypt
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
  }
}
