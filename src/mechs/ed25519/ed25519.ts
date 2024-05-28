import * as core from "webcrypto-core";
import { Ed25519Crypto } from "./crypto";
import { Ed25519CryptoKey } from "./crypto_key";
import { Ed25519PrivateKey } from "./private_key";
import { Ed25519PublicKey } from "./public_key";
import { getCryptoKey, setCryptoKey } from "../storage";

export class Ed25519Provider extends core.Ed25519Provider {
  public override async onGenerateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await Ed25519Crypto.generateKey(algorithm, extractable, keyUsages);
    return {
      privateKey: setCryptoKey(keys.privateKey as Ed25519CryptoKey),
      publicKey: setCryptoKey(keys.publicKey as Ed25519CryptoKey),
    };
  }

  override async onSign(algorithm: Algorithm, key: Ed25519PrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const internalKey = getCryptoKey(key) as Ed25519PrivateKey;
    const signature = Ed25519Crypto.sign(algorithm, internalKey, new Uint8Array(data));
    return signature;
  }

  override onVerify(algorithm: Algorithm, key: Ed25519PublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const internalKey = getCryptoKey(key) as Ed25519PublicKey;
    return Ed25519Crypto.verify(algorithm, internalKey, new Uint8Array(signature), new Uint8Array(data));
  }

  override async onExportKey(format: KeyFormat, key: Ed25519CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const internalKey = getCryptoKey(key) as Ed25519CryptoKey;
    return Ed25519Crypto.exportKey(format, internalKey);
  }

  override async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const internalKey = await Ed25519Crypto.importKey(format, keyData, algorithm, extractable, keyUsages);
    return setCryptoKey(internalKey);
  }
}
