import * as types from "@peculiar/webcrypto-types";
import type * as graphene from "graphene-pk11";

import { IContainer, ISessionContainer } from "../../types";

export class ShaCrypto implements IContainer {

  public constructor(public container: ISessionContainer) { }

  public async digest(algorithm: types.Algorithm, data: ArrayBuffer) {
    const p11Mech: graphene.IAlgorithm = {
      name: algorithm.name.toUpperCase().replace("-", ""),
      params: null,
    };

    return new Promise<ArrayBuffer>((resolve, reject) => {
      this.container.session.createDigest(p11Mech).once(Buffer.from(data), (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data).buffer);
        }
      });
    });
  }

}
