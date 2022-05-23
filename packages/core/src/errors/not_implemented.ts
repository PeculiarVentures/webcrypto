import { CryptoError } from "./crypto";

export class UnsupportedOperationError extends CryptoError {
  constructor(methodName?: string) {
    super(`Unsupported operation: ${methodName ? `${methodName}` : ""}`);
  }
}
