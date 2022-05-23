import * as graphene from "graphene-pk11";
import { CryptoKey } from "./key";

export class Assert {
  /**
   * Throws exception whenever data is not an instance of Session
   * @param data
   * @throws TypeError
   */
  public static isSession(data: any): asserts data is graphene.Session {
    if (!(data instanceof graphene.Session)) {
      throw new TypeError("PKCS#11 session is not initialized");
    }
  }

  /**
   * Throws exception whenever data is not an instance of Module
   * @param data
   * @throws TypeError
   */
  public static isModule(data: any): asserts data is graphene.Module {
    if (!(data instanceof graphene.Module)) {
      throw new TypeError("PKCS#11 module is not initialized");
    }
  }

  /**
   * Throws exception whenever data is not an instance of PKCS#11 CryptoKey
   * @param data
   * @throws TypeError
   */
  public static isCryptoKey(data: any): asserts data is CryptoKey {
    if (!(data instanceof CryptoKey)) {
      throw new TypeError("Object is not an instance of PKCS#11 CryptoKey");
    }
  }

  public static requiredParameter(parameter: any, parameterName: string): asserts parameter {
    if (!parameter) {
      throw new Error(`Absent mandatory parameter \"${parameterName}\"`);
    }
  }

}
