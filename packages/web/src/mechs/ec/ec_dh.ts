import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdhProvider extends core.EcdhProvider {

  public override namedCurves = ["P-256", "P-384", "P-521", "K-256", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"];

  public async onGenerateKey(algorithm: types.EcKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<types.CryptoKeyPair> {
    return EcCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: types.KeyFormat, key: EcCryptoKey): Promise<ArrayBuffer | types.JsonWebKey> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.EcKeyImportParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<EcCryptoKey> {
    return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onDeriveBits(algorithm: types.EcdhKeyDeriveParams, baseKey: EcCryptoKey, length: number): Promise<ArrayBuffer> {
    EcCrypto.checkLib();

    const shared = baseKey.data.derive((algorithm.public as EcCryptoKey).data.getPublic());
    let array = new Uint8Array(shared.toArray());

    // Padding
    let len = array.length;
    len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
    if (array.length < len) {
      array = EcCrypto.concat(new Uint8Array(len - array.length), array);
    }
    const buf = array.slice(0, length / 8).buffer;
    return buf;
  }

  public override checkCryptoKey(key: EcCryptoKey, keyUsage: types.KeyUsage): asserts key is EcCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(key);
  }

}
