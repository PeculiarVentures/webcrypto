import crypto from "crypto";
import * as core from "webcrypto-core";
import { Ed25519Crypto } from "./crypto";
import { Ed25519CryptoKey } from "./crypto_key";
import { CryptoKey } from "../../keys";
import { getCryptoKey, setCryptoKey } from "../storage";

export class X25519Provider extends core.X25519Provider {
  public override async onGenerateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await Ed25519Crypto.generateKey(algorithm, extractable, keyUsages);
    return {
      privateKey: setCryptoKey(keys.privateKey as Ed25519CryptoKey),
      publicKey: setCryptoKey(keys.publicKey as Ed25519CryptoKey),
    };
  }

  public override async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: Ed25519CryptoKey, length: number): Promise<ArrayBuffer> {
    const internalBaseKey = getCryptoKey(baseKey);
    const internalPublicKey = getCryptoKey(algorithm.public);
    const publicKey = crypto.createPublicKey({
      key: internalPublicKey.data.toString(),
      format: "pem",
      type: "spki",
    });
    const privateKey = crypto.createPrivateKey({
      key: internalBaseKey.data.toString(),
      format: "pem",
      type: "pkcs8",
    });
    const bits = crypto.diffieHellman({
      publicKey,
      privateKey,
    });

    return new Uint8Array(bits).buffer.slice(0, length >> 3);
  }

  public override async onExportKey(format: KeyFormat, key: Ed25519CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const internalKey = getCryptoKey(key);
    return Ed25519Crypto.exportKey(format, internalKey as Ed25519CryptoKey);
  }

  public override async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await Ed25519Crypto.importKey(format, keyData, algorithm, extractable, keyUsages);
    return setCryptoKey(key);
  }

  override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage | undefined): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof Ed25519CryptoKey)) {
      throw new TypeError("key: Is not a Ed25519CryptoKey");
    }
  }
}
