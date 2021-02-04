import * as core from "webcrypto-core";

const edOIDs: { [key: string]: string } = {
  // Ed448
  [core.asn1.idEd448]: "Ed448",
  "ed448": core.asn1.idEd448,
  // X448
  [core.asn1.idX448]: "X448",
  "x448": core.asn1.idX448,
  // Ed25519
  [core.asn1.idEd25519]: "Ed25519",
  "ed25519": core.asn1.idEd25519,
  // X25519
  [core.asn1.idX25519]: "X25519",
  "x25519": core.asn1.idX25519,
};

export function getNamedCurveByOid(oid: string) {
  const namedCurve = edOIDs[oid];
  if (!namedCurve) {
    throw new core.OperationError(`Cannot convert OID(${oid}) to WebCrypto named curve`);
  }
  return namedCurve;
}

export function getOidByNamedCurve(namedCurve: string) {
  const oid = edOIDs[namedCurve.toLowerCase()];
  if (!oid) {
    throw new core.OperationError(`Cannot convert WebCrypto named curve '${namedCurve}' to OID`);
  }
  return oid;
}
