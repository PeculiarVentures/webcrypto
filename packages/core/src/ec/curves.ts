import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1 from "../schema/asn1";

export interface EcCurveParams {
  /**
   * The name of the curve
   */
  name: string;
  /**
   * The object identifier of the curve
   */
  id: string;
  /**
   * Curve point size in bits
   */
  size: number;
}

export interface EcCurve extends EcCurveParams {
  raw: ArrayBuffer;
}

export class EcCurves {

  protected static items: EcCurve[] = [];
  public static readonly names: string[] = [];

  private constructor() { }

  public static register(item: EcCurveParams) {
    const oid = new asn1.ObjectIdentifier();
    oid.value = item.id;
    const raw = AsnConvert.serialize(oid);

    this.items.push({
      ...item,
      raw,
    });
    this.names.push(item.name);
  }

  public static find(nameOrId: string): EcCurve | null {
    nameOrId = nameOrId.toUpperCase();
    for (const item of this.items) {
      if (item.name.toUpperCase() === nameOrId || item.id.toUpperCase() === nameOrId) {
        return item;
      }
    }

    return null;
  }

  public static get(nameOrId: string): EcCurve {
    const res = this.find(nameOrId);
    if (!res) {
      throw new Error(`Unsupported EC named curve '${nameOrId}'`);
    }

    return res;
  }

}

EcCurves.register({ name: "P-256", id: asn1.idSecp256r1, size: 256 });
EcCurves.register({ name: "P-384", id: asn1.idSecp384r1, size: 384 });
EcCurves.register({ name: "P-521", id: asn1.idSecp521r1, size: 521 });
EcCurves.register({ name: "K-256", id: asn1.idSecp256k1, size: 256 });
EcCurves.register({ name: "brainpoolP160r1", id: asn1.idBrainpoolP160r1, size: 160 });
EcCurves.register({ name: "brainpoolP160t1", id: asn1.idBrainpoolP160t1, size: 160 });
EcCurves.register({ name: "brainpoolP192r1", id: asn1.idBrainpoolP192r1, size: 192 });
EcCurves.register({ name: "brainpoolP192t1", id: asn1.idBrainpoolP192t1, size: 192 });
EcCurves.register({ name: "brainpoolP224r1", id: asn1.idBrainpoolP224r1, size: 224 });
EcCurves.register({ name: "brainpoolP224t1", id: asn1.idBrainpoolP224t1, size: 224 });
EcCurves.register({ name: "brainpoolP256r1", id: asn1.idBrainpoolP256r1, size: 256 });
EcCurves.register({ name: "brainpoolP256t1", id: asn1.idBrainpoolP256t1, size: 256 });
EcCurves.register({ name: "brainpoolP320r1", id: asn1.idBrainpoolP320r1, size: 320 });
EcCurves.register({ name: "brainpoolP320t1", id: asn1.idBrainpoolP320t1, size: 320 });
EcCurves.register({ name: "brainpoolP384r1", id: asn1.idBrainpoolP384r1, size: 384 });
EcCurves.register({ name: "brainpoolP384t1", id: asn1.idBrainpoolP384t1, size: 384 });
EcCurves.register({ name: "brainpoolP512r1", id: asn1.idBrainpoolP512r1, size: 512 });
EcCurves.register({ name: "brainpoolP512t1", id: asn1.idBrainpoolP512t1, size: 512 });
