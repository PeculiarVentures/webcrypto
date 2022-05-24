declare module "des.js" {

  type DesOperationType = "encrypt" | "decrypt" | string;

  class Cipher {
    public update(data: Uint8Array): number[];
    public final(): number[];
  }

  interface IDesCreateParams {
    key: Uint8Array;
    type: DesOperationType;
    iv?: Uint8Array;
  }

  class DES extends Cipher {
    public static create(params: IDesCreateParams): DES;
  }

  class EDE extends DES {
    public static create(params: IDesCreateParams): EDE;
  }

  class CBC {
    public static instantiate(type: typeof DES): typeof DES;
  }

}
