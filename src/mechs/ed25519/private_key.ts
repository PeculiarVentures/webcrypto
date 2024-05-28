import crypto from "crypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import * as core from "webcrypto-core";
import { Ed25519CryptoKey } from "./crypto_key";

export class Ed25519PrivateKey extends Ed25519CryptoKey {
  public override type = "private" as const;

  public override toJWK(): JsonWebKey {
    const pubJwk = crypto.createPublicKey({
      key: this.data,
      format: "pem",
    }).export({ format: "jwk" }) as JsonWebKey;
    const raw = core.PemConverter.toUint8Array(this.data.toString());
    const pkcs8 = AsnConvert.parse(raw, core.asn1.PrivateKeyInfo);
    const d = AsnConvert.parse(pkcs8.privateKey, core.asn1.EdPrivateKey).value;
    return {
      ...super.toJWK(),
      ...pubJwk,
      d: Buffer.from(new Uint8Array(d)).toString("base64url"),
    };
  }
}
