import * as types from "@peculiar/webcrypto-types";
import * as core from "@peculiar/webcrypto-core";

import { ID_DIGEST } from "./const";
import { CryptoKey, CryptoKey as P11CryptoKey } from "./key";
import * as mechs from "./mechs";
import { IContainer, ISessionContainer } from "./types";
import * as utils from "./utils";

export class SubtleCrypto extends core.SubtleCrypto implements IContainer {

  public constructor(public container: ISessionContainer) {
    super();

    //#region AES
    this.providers.set(new mechs.AesCbcProvider(this.container));
    this.providers.set(new mechs.AesEcbProvider(this.container));
    this.providers.set(new mechs.AesGcmProvider(this.container));
    //#endregion
    // #region RSA
    this.providers.set(new mechs.RsaSsaProvider(this.container));
    this.providers.set(new mechs.RsaPssProvider(this.container));
    this.providers.set(new mechs.RsaOaepProvider(this.container));
    // #endregion
    // #region EC
    this.providers.set(new mechs.EcdsaProvider(this.container));
    this.providers.set(new mechs.EcdhProvider(this.container));
    // #endregion
    //#region SHA
    this.providers.set(new mechs.Sha1Provider(this.container));
    this.providers.set(new mechs.Sha256Provider(this.container));
    this.providers.set(new mechs.Sha384Provider(this.container));
    this.providers.set(new mechs.Sha512Provider(this.container));
    //#endregion
    // #region HMAC
    this.providers.set(new mechs.HmacProvider(this.container));
    // #endregion
  }

  public override async generateKey(algorithm: types.RsaHashedKeyGenParams | types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair>;
  public override async generateKey(algorithm: types.AesKeyGenParams | types.HmacKeyGenParams | types.Pbkdf2Params, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey>;
  public override async generateKey(algorithm: types.AlgorithmIdentifier, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair | types.CryptoKey> {
    const keys = await super.generateKey(algorithm, extractable, keyUsages);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (utils.isCryptoKeyPair(keys)) {
      const publicKey = keys.publicKey as P11CryptoKey;
      const privateKey = keys.privateKey as P11CryptoKey;

      const raw = await this.exportKey("spki", publicKey);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);
      privateKey.key.id = digest;
      privateKey.id = P11CryptoKey.getID(privateKey.key);
    }

    return keys;
  }

  public override async importKey(format: types.KeyFormat, keyData: types.JsonWebKey | types.BufferSource, algorithm: types.AlgorithmIdentifier, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    const key = await super.importKey(format, keyData, algorithm, extractable, keyUsages);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (key.type === "public" && extractable) {
      const publicKey = key as P11CryptoKey;

      const raw = await this.exportKey("spki", publicKey);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);
    }

    return key as CryptoKey;
  }

}
