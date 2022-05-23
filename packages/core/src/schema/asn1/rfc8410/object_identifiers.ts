/**
 * ```
 * secp256r1 OBJECT IDENTIFIER ::= {
 *    iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
 *    prime(1) 7 }
 * ```
 */
export const idSecp256r1 = "1.2.840.10045.3.1.7";
/**
 * ```
 * ellipticCurve OBJECT IDENTIFIER ::= {
 *    iso(1) identified-organization(3) certicom(132) curve(0) }
 * ```
 */
export const idEllipticCurve = "1.3.132.0";
/**
 * ```
 * secp384r1 OBJECT IDENTIFIER ::= { ellipticCurve 34 }
 * ```
 */
export const idSecp384r1 = `${idEllipticCurve}.34`;
/**
 * ```
 * secp521r1 OBJECT IDENTIFIER ::= { ellipticCurve 35 }
 * ```
 */
export const idSecp521r1 = `${idEllipticCurve}.35`;
/**
 * ```
 * secp256k1 OBJECT IDENTIFIER ::= { ellipticCurve 10 }
 * ```
 */
export const idSecp256k1 = `${idEllipticCurve}.10`;
/**
 * ```
 * ecStdCurvesAndGeneration OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) teletrust(36) algorithm(3)
 *   signature-algorithm(3) ecSign(2) ecStdCurvesAndGeneration(8)
 * }
 * ellipticCurve OBJECT IDENTIFIER ::= { ecStdCurvesAndGeneration 1 }
 * versionOne OBJECT IDENTIFIER ::= { ellipticCurve 1 }
 * ```
 */
export const idVersionOne = "1.3.36.3.3.2.8.1.1";
/**
 * ```
 * brainpoolP160r1 OBJECT IDENTIFIER ::= { versionOne 1 }
 * ```
 */
export const idBrainpoolP160r1 = `${idVersionOne}.1`;
/**
 * ```
 * brainpoolP160t1 OBJECT IDENTIFIER ::= { versionOne 2 }
 * ```
 */
export const idBrainpoolP160t1 = `${idVersionOne}.2`;
/**
 * ```
 * brainpoolP192r1 OBJECT IDENTIFIER ::= { versionOne 3 }
 * ```
 */
export const idBrainpoolP192r1 = `${idVersionOne}.3`;
/**
 * ```
 * brainpoolP192t1 OBJECT IDENTIFIER ::= { versionOne 4 }
 * ```
 */
export const idBrainpoolP192t1 = `${idVersionOne}.4`;
/**
 * ```
 * brainpoolP224r1 OBJECT IDENTIFIER ::= { versionOne 5 }
 * ```
 */
export const idBrainpoolP224r1 = `${idVersionOne}.5`;
/**
 * ```
 * brainpoolP224t1 OBJECT IDENTIFIER ::= { versionOne 6 }
 * ```
 */
export const idBrainpoolP224t1 = `${idVersionOne}.6`;
/**
 * ```
 * brainpoolP256r1 OBJECT IDENTIFIER ::= { versionOne 7 }
 * ```
 */
export const idBrainpoolP256r1 = `${idVersionOne}.7`;
/**
 * ```
 * brainpoolP256t1 OBJECT IDENTIFIER ::= { versionOne 8 }
 * ```
 */
export const idBrainpoolP256t1 = `${idVersionOne}.8`;
/**
 * ```
 * brainpoolP320r1 OBJECT IDENTIFIER ::= { versionOne 9 }
 * ```
 */
export const idBrainpoolP320r1 = `${idVersionOne}.9`;
/**
 * ```
 * brainpoolP320t1 OBJECT IDENTIFIER ::= { versionOne 10 }
 * ```
 */
export const idBrainpoolP320t1 = `${idVersionOne}.10`;
/**
 * ```
 * brainpoolP384r1 OBJECT IDENTIFIER ::= { versionOne 11 }
 * ```
 */
export const idBrainpoolP384r1 = `${idVersionOne}.11`;
/**
 * ```
 * brainpoolP384t1 OBJECT IDENTIFIER ::= { versionOne 12 }
 * ```
 */
export const idBrainpoolP384t1 = `${idVersionOne}.12`;
/**
 * ```
 * brainpoolP512r1 OBJECT IDENTIFIER ::= { versionOne 13 }
 * ```
 */
export const idBrainpoolP512r1 = `${idVersionOne}.13`;
/**
 * ```
 * brainpoolP512t1 OBJECT IDENTIFIER ::= { versionOne 14 }
 * ```
 */
export const idBrainpoolP512t1 = `${idVersionOne}.14`;
/**
 * ```
 * id-X25519 OBJECT IDENTIFIER ::= { 1 3 101 110 }
 * ```
 */
export const idX25519 = "1.3.101.110";
/**
 * ```
 * id-X448 OBJECT IDENTIFIER ::= { 1 3 101 111 }
 * ```
 */
export const idX448 = "1.3.101.111";
/**
 * ```
 * id-Ed25519 OBJECT IDENTIFIER ::= { 1 3 101 112 }
 * ```
 */
export const idEd25519 = "1.3.101.112";
/**
 * ```
 * id-Ed448 OBJECT IDENTIFIER ::= { 1 3 101 113 }
 * ```
 */
export const idEd448 = "1.3.101.113";
