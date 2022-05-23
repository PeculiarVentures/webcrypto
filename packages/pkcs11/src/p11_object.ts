import { Storage } from "graphene-pk11";

export class Pkcs11Object {

  public static assertStorage(obj: Storage | undefined): asserts obj is Storage {
    if (!obj) {
      throw new TypeError("PKCS#11 object is empty");
    }
  }

  public p11Object?: Storage;

  constructor(object?: Storage) {
    this.p11Object = object;
  }

}
