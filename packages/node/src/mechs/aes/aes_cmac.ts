import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as crypto from "crypto";
import { setCryptoKey, getCryptoKey } from "../storage";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

/**
 * AES-CMAC implementation source code from https://github.com/allan-stewart/node-aes-cmac
 */

const zero = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const rb = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135]);
const blockSize = 16;

function bitShiftLeft(buffer: Buffer) {
  const shifted = Buffer.alloc(buffer.length);
  const last = buffer.length - 1;
  for (let index = 0; index < last; index++) {
    shifted[index] = buffer[index] << 1;
    if (buffer[index + 1] & 0x80) {
      shifted[index] += 0x01;
    }
  }
  shifted[last] = buffer[last] << 1;
  return shifted;
}

function xor(a: Buffer, b: Buffer) {
  const length = Math.min(a.length, b.length);
  const output = Buffer.alloc(length);

  for (let index = 0; index < length; index++) {
    output[index] = a[index] ^ b[index];
  }
  return output;
}

function aes(key: Buffer, message: Buffer) {
  const cipher = crypto.createCipheriv(`aes${key.length << 3}`, key, zero);
  const result = cipher.update(message);
  cipher.final();
  return result;
}

function getMessageBlock(message: Buffer, blockIndex: number) {
  const block = Buffer.alloc(blockSize);
  const start = blockIndex * blockSize;
  const end = start + blockSize;

  message.copy(block, 0, start, end);

  return block;
}

function getPaddedMessageBlock(message: Buffer, blockIndex: number) {
  const block = Buffer.alloc(blockSize);
  const start = blockIndex * blockSize;
  const end = message.length;

  block.fill(0);
  message.copy(block, 0, start, end);
  block[end - start] = 0x80;

  return block;
}

function generateSubkeys(key: Buffer) {
  const l = aes(key, zero);

  let subkey1 = bitShiftLeft(l);
  if (l[0] & 0x80) {
    subkey1 = xor(subkey1, rb);
  }

  let subkey2 = bitShiftLeft(subkey1);
  if (subkey1[0] & 0x80) {
    subkey2 = xor(subkey2, rb);
  }

  return { subkey1, subkey2 };
}

function aesCmac(key: Buffer, message: Buffer) {
  const subkeys = generateSubkeys(key);
  let blockCount = Math.ceil(message.length / blockSize);
  let lastBlockCompleteFlag: boolean;
  let lastBlock: Buffer;

  if (blockCount === 0) {
    blockCount = 1;
    lastBlockCompleteFlag = false;
  } else {
    lastBlockCompleteFlag = (message.length % blockSize === 0);
  }
  const lastBlockIndex = blockCount - 1;

  if (lastBlockCompleteFlag) {
    lastBlock = xor(getMessageBlock(message, lastBlockIndex), subkeys.subkey1);
  } else {
    lastBlock = xor(getPaddedMessageBlock(message, lastBlockIndex), subkeys.subkey2);
  }

  let x = zero;
  let y;

  for (let index = 0; index < lastBlockIndex; index++) {
    y = xor(x, getMessageBlock(message, index));
    x = aes(key, y);
  }
  y = xor(lastBlock, x);
  return aes(key, y);
}

export class AesCmacProvider extends core.AesCmacProvider {

  public async onGenerateKey(algorithm: types.AesKeyGenParams, extractable: boolean, keyUsages: types.KeyUsage[]): Promise<core.CryptoKey> {
    const key = await AesCrypto.generateKey(
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return setCryptoKey(key);
  }

  public async onSign(algorithm: types.AesCmacParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const result = aesCmac(getCryptoKey(key).data, Buffer.from(data));
    return new Uint8Array(result).buffer;
  }

  public async onVerify(algorithm: types.AesCmacParams, key: AesCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const signature2 = await this.sign(algorithm, key, data);
    return Buffer.from(signature).compare(Buffer.from(signature2)) === 0;
  }

  public async onExportKey(format: types.KeyFormat, key: AesCryptoKey): Promise<types.JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(format, getCryptoKey(key) as AesCryptoKey);

  }

  public async onImportKey(format: types.KeyFormat, keyData: ArrayBuffer | types.JsonWebKey, algorithm: types.Algorithm, extractable: boolean, keyUsages: types.KeyUsage[], ...args: any[]): Promise<core.CryptoKey> {
    const res = await AesCrypto.importKey(format, keyData, { name: algorithm.name }, extractable, keyUsages);
    return setCryptoKey(res);
  }

  public override checkCryptoKey(key: core.CryptoKey, keyUsage?: types.KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(getCryptoKey(key) instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not a AesCryptoKey");
    }
  }
}
