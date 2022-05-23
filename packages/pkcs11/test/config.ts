import * as os from "os";
import { Crypto } from "../src";

export const config = process.env.PV_CRYPTO === "nss" ?
  {
    library: os.platform() === "darwin" ? "/usr/local/opt/nss/lib/libsoftokn3.dylib" : "/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
    libraryParameters: `configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen,optimizeSpace`,
    name: "NSS",
    slot: 1,
    readWrite: true,
  }
  :
  {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSMv2",
    slot: 0,
    readWrite: true,
    pin: "12345",
  };

console.log(`PKCS11 provider: ${config.name} at ${config.library}`);
export const crypto = new Crypto(config);

process.on("beforeExit", () => {
  crypto.close();
});
