import { CryptoKey } from "./key";

export class SymmetricKey extends CryptoKey {

  public override readonly kty = "oct";
  public override readonly type = "secret" as const;

}
