import { CryptoError } from "./crypto";

export class RequiredPropertyError extends CryptoError {
  constructor(propName: string, target?: string) {
    super(`${propName}: Missing required property${target ? ` in ${target}` : ""}`);
  }
}
