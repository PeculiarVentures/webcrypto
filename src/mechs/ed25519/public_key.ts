import crypto from "crypto";
import { Ed25519CryptoKey } from "./crypto_key";

export class Ed25519PublicKey extends Ed25519CryptoKey {
  public override type = "public" as const;

  public override toJWK(): JsonWebKey {
    const jwk = crypto.createPublicKey({
      key: this.data,
      format: "pem",
    }).export({ format: "jwk" }) as JsonWebKey;

    return {
      ...super.toJWK(),
      ...jwk,
    };
  }
}
