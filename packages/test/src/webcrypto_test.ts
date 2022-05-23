import * as types from "@peculiar/webcrypto-types";
import { testCrypto } from "./helper";
import { ITestParams, ITestVectorsExclude } from "./types";
import * as Vectors from "./vectors";

export class WebcryptoTest {

  /**
   * Adds non default check
   * @param func
   */
  public static add(crypto: types.Crypto, param: ITestParams) {
    testCrypto(crypto, param);
  }

  /**
   * Default check
   * @param crypto
   * @param vectors
   */
  public static check(crypto: types.Crypto, vectors?: ITestParams[] | ITestVectorsExclude) {
    if (Array.isArray(vectors)) {
      vectors.forEach((element) => {
        testCrypto(crypto, element);
      });
    } else {
      for (const key in Vectors) {
        if (!vectors?.[key]) {
          testCrypto(crypto, (Vectors as any)[key]);
        }
      }
    }
  }
}
