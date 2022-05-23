import { EcdhProvider } from "./ecdh";

export abstract class EcdhEsProvider extends EcdhProvider {
  public override readonly name: string = "ECDH-ES";

  public override namedCurves = ["X25519", "X448"];
}