import * as types from "@peculiar/webcrypto-types";
import * as core from "@peculiar/webcrypto-core";

import { Assert } from "../../assert";
import { CryptoKey } from "../../key";
import { IContainer, ISessionContainer } from "../../types";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCbcProvider extends core.AesCbcProvider implements IContainer {

  public crypto: AesCrypto;

  constructor(public container: ISessionContainer) {
    super();

    this.crypto = new AesCrypto(container);
  }

  public override async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<core.CryptoKey> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public override async onEncrypt(algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.encrypt(false, algorithm, key, new Uint8Array(data));
  }

  public override async onDecrypt(algorithm: types.Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.decrypt(false, algorithm, key, new Uint8Array(data));
  }

  public override async onExportKey(format: types.KeyFormat, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public override async onImportKey(format: types.KeyFormat, keyData: types.JsonWebKey | ArrayBuffer, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<CryptoKey> {
    return this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    Assert.isCryptoKey(key);
  }

}
