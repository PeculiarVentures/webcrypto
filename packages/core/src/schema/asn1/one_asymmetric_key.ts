import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "./private_key_info";

/**
 * ```asn
 * OneAsymmetricKey ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] IMPLICIT Attributes OPTIONAL,
 *   ...,
 *   [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
 *   ...
 * }
 *
 * PrivateKey ::= OCTET STRING
 *
 * PublicKey ::= BIT STRING
 * ```
 */
export class OneAsymmetricKey extends PrivateKeyInfo {

  @AsnProp({ context: 1, implicit: true, type: AsnPropTypes.BitString, optional: true })
  public publicKey?: ArrayBuffer;

}