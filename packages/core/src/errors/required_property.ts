import { CryptoError } from "./crypto";

export class RequiredPropertyError extends CryptoError {
  constructor(propName: string) {
    super(`${propName}: Missing required property`);
  }
}
