import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";

import { IContainer, ISessionContainer } from "../../types";
import { ShaCrypto } from "./crypto";

export class Sha1Provider extends core.ProviderCrypto implements IContainer {
  public name = "SHA-1";
  public usages: types.KeyUsage[] = [];
  public crypto: ShaCrypto;

  constructor(public container: ISessionContainer) {
    super();

    this.crypto = new ShaCrypto(container);
  }

  public override async onDigest(algorithm: types.Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.digest(algorithm, data);
  }

}
