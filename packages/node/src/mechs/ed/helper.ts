import * as core from "@peculiar/webcrypto-core";
import * as schema from "packages/core/src/schema";

const edOIDs: { [key: string]: string; } = {
  // Ed448
  [schema.idEd448]: "Ed448",
  "ed448": schema.idEd448,
  // X448
  [schema.idX448]: "X448",
  "x448": schema.idX448,
  // Ed25519
  [schema.idEd25519]: "Ed25519",
  "ed25519": schema.idEd25519,
  // X25519
  [schema.idX25519]: "X25519",
  "x25519": schema.idX25519,
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
