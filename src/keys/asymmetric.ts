import { CryptoKey } from "./key";

export abstract class AsymmetricKey extends CryptoKey {

  public abstract type: "public" | "private";
  public pem?: string;

}
