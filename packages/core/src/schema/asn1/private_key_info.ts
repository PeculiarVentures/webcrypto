import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "./algorithm_identifier";

// RFC 5208
// https://tools.ietf.org/html/rfc5208#section-5
//
// PrivateKeyInfo ::= SEQUENCE {
//   version                   Version,
//   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//   privateKey                PrivateKey,
//   attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
// Version ::= INTEGER
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// PrivateKey ::= OCTET STRING
//
// Attributes ::= SET OF Attribute

export class PrivateKeyInfo {

  @AsnProp({ type: AsnPropTypes.Integer })
  public version = 0;

  @AsnProp({ type: AlgorithmIdentifier })
  public privateKeyAlgorithm = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.OctetString })
  public privateKey = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Any, optional: true })
  public attributes?: ArrayBuffer;

}
