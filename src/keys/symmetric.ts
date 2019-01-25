import { CryptoKey } from "./key";

export class SymmetricKey extends CryptoKey {

  public readonly kty = "oct";
  public readonly type: "secret" = "secret";

}
