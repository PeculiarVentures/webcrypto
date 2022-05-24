import * as core from "@peculiar/webcrypto-core";

// TODO Use EcCurve from core
const namedOIDs: { [key: string]: string; } = {
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
  // brainpoolP256r1
  "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
  "brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7",
  // brainpoolP384r1
  "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
  "brainpoolP384r1": "1.3.36.3.3.2.8.1.1.11",
  // brainpoolP512r1
  "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
  "brainpoolP512r1": "1.3.36.3.3.2.8.1.1.13",
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
