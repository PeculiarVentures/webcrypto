import * as types from "@peculiar/webcrypto-types";
import { AesProvider } from "./base";

export abstract class AesKwProvider extends AesProvider {

  public readonly name = "AES-KW";

  public usages: types.KeyUsages = ["wrapKey", "unwrapKey"];

}
