import { Convert } from "pvtsutils";
import { ITestParams } from "../types";

const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

export const SHA: ITestParams = {
  name: "SHA",
  actions: {
    digest: [
      {
        name: "SHA-1",
        algorithm: "SHA-1",
        data,
        hash: Convert.FromBase64("6JrVqWMcPv3e1+Psznm00P7c4b8="),
      },
      {
        name: "SHA-256",
        algorithm: "SHA-256",
        data,
        hash: Convert.FromBase64("monGjExeKLjEpVZ2c9Ri//UV20YRb5kAYk0JxHT1k/s="),
      },
      {
        name: "SHA-384",
        algorithm: "SHA-384",
        data,
        hash: Convert.FromBase64("E9WqubQC9JnxffIniWwf0soI91o5z0Kbvk+s/32Fi3z28kAh+Fcne7Hgy1nnW4rR"),
      },
      {
        name: "SHA-512",
        algorithm: "SHA-512",
        data,
        hash: Convert.FromBase64("OtPzaXlFDU9TNmJE7PEBD0+RIdaIgoX/FBBP1a3thdSKoXG/HjOhEmAvkrenCIsph4kBL7h7kFYyEkGhn7dOCw=="),
      },
    ],
  },
};