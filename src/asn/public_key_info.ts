import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "./algorithm_identifier";

// RFC 5280
// https://tools.ietf.org/html/rfc5280#section-4.1
//
// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//   algorithm            AlgorithmIdentifier,
//   subjectPublicKey     BIT STRING

export class PublicKeyInfo {

  @AsnProp({ type: AlgorithmIdentifier })
  public publicKeyAlgorithm = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.BitString })
  public publicKey = new ArrayBuffer(0);

}
