import nodeCrypto from "node:crypto";
import process from "node:process";
import { WebcryptoTest } from "@peculiar/webcrypto-test";
import { describe, it } from "vitest";
import { Crypto } from "./crypto";

const nodeMajorVersion = parseInt(/^v(\d+)/.exec(process.version)![1], 10);

const ciphers = nodeCrypto.getCiphers();

// Shared WebCrypto test suite from @peculiar/webcrypto-test
WebcryptoTest.check(
  new Crypto() as any,
  {
    DESCBC: !ciphers.includes("des-cbc"),
    RSAESPKCS1: nodeMajorVersion >= 18,
  },
  { describe, it },
);
