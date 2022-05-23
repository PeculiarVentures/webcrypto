import { ShakeProvider } from "./base";

export abstract class Shake128Provider extends ShakeProvider {
  public override name = "shake128";
  public override defaultLength = 16;
}
