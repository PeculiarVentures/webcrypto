import { ShakeProvider } from "./base";

export abstract class Shake256Provider extends ShakeProvider {
  public override name = "shake256";
  public override defaultLength = 32;
}
