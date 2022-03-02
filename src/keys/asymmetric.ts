import { CryptoKey } from "./key";

export abstract class AsymmetricKey extends CryptoKey {

  public abstract override type: "public" | "private";
  public pem?: string;

}
