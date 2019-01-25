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
