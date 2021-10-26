import * as core from "webcrypto-core";

const namedOIDs: { [key: string]: string } = {
  // P-256
  "1.2.840.10045.3.1.7": "P-256",
  "P-256": "1.2.840.10045.3.1.7",
  // P-384
  "1.3.132.0.34": "P-384",
  "P-384": "1.3.132.0.34",
  // P-521
  "1.3.132.0.35": "P-521",
  "P-521": "1.3.132.0.35",
  // K-256
  "1.3.132.0.10": "K-256",
  "K-256": "1.3.132.0.10",

  // brainpool
  "brainpoolP160r1": "1.3.36.3.3.2.8.1.1.1",
  "1.3.36.3.3.2.8.1.1.1": "brainpoolP160r1",
  "brainpoolP160t1": "1.3.36.3.3.2.8.1.1.2",
  "1.3.36.3.3.2.8.1.1.2": "brainpoolP160t1",
  "brainpoolP192r1": "1.3.36.3.3.2.8.1.1.3",
  "1.3.36.3.3.2.8.1.1.3": "brainpoolP192r1",
  "brainpoolP192t1": "1.3.36.3.3.2.8.1.1.4",
  "1.3.36.3.3.2.8.1.1.4": "brainpoolP192t1",
  "brainpoolP224r1": "1.3.36.3.3.2.8.1.1.5",
  "1.3.36.3.3.2.8.1.1.5": "brainpoolP224r1",
  "brainpoolP224t1": "1.3.36.3.3.2.8.1.1.6",
  "1.3.36.3.3.2.8.1.1.6": "brainpoolP224t1",
  "brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7",
  "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
  "brainpoolP256t1": "1.3.36.3.3.2.8.1.1.8",
  "1.3.36.3.3.2.8.1.1.8": "brainpoolP256t1",
  "brainpoolP320r1": "1.3.36.3.3.2.8.1.1.9",
  "1.3.36.3.3.2.8.1.1.9": "brainpoolP320r1",
  "brainpoolP320t1": "1.3.36.3.3.2.8.1.1.10",
  "1.3.36.3.3.2.8.1.1.10": "brainpoolP320t1",
  "brainpoolP384r1": "1.3.36.3.3.2.8.1.1.11",
  "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
  "brainpoolP384t1": "1.3.36.3.3.2.8.1.1.12",
  "1.3.36.3.3.2.8.1.1.12": "brainpoolP384t1",
  "brainpoolP512r1": "1.3.36.3.3.2.8.1.1.13",
  "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
  "brainpoolP512t1": "1.3.36.3.3.2.8.1.1.14",
  "1.3.36.3.3.2.8.1.1.14": "brainpoolP512t1",
};

export function getNamedCurveByOid(oid: string) {
  const namedCurve = namedOIDs[oid];
  if (!namedCurve) {
    throw new core.OperationError(`Cannot convert OID(${oid}) to WebCrypto named curve`);
  }
  return namedCurve;
}

export function getOidByNamedCurve(namedCurve: string) {
  const oid = namedOIDs[namedCurve];
  if (!oid) {
    throw new core.OperationError(`Cannot convert WebCrypto named curve '${namedCurve}' to OID`);
  }
  return oid;
}
