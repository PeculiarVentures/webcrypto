import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { BufferSourceConverter, BufferSource } from "pvtsutils";
import { EcUtils } from "../../ec/utils";
import { AsnIntegerWithoutPaddingConverter } from "./converters";

// RFC 3279
// https://tools.ietf.org/html/rfc3279#section-2.2.3
//
// ECDSA-Sig-Value ::= SEQUENCE {
//   r  INTEGER,
//   s  INTEGER
// }

export class EcDsaSignature {

  /**
   * Create EcDsaSignature from X9.62 signature
   * @param value X9.62 signature
   * @returns EcDsaSignature
   */
  public static fromWebCryptoSignature(value: BufferSource): EcDsaSignature {
    const pointSize = value.byteLength / 2;

    const point = EcUtils.decodeSignature(value, pointSize * 8);
    const ecSignature = new EcDsaSignature();
    ecSignature.r = BufferSourceConverter.toArrayBuffer(point.r);
    ecSignature.s = BufferSourceConverter.toArrayBuffer(point.s);

    return ecSignature;
  }

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public r = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerWithoutPaddingConverter })
  public s = new ArrayBuffer(0);

  /**
   * Converts ECDSA signature into X9.62 signature format
   * @param pointSize EC point size in bits
   * @returns ECDSA signature in X9.62 signature format
   */
  public toWebCryptoSignature(pointSize?: number): ArrayBuffer {
    pointSize ??= Math.max(this.r.byteLength, this.s.byteLength) * 8;

    const signature = EcUtils.encodeSignature(this, pointSize);

    return signature.buffer;
  }

}
