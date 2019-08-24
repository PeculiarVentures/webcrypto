import * as core from "webcrypto-core";

export function getJwkAlgorithm(algorithm: RsaHashedKeyAlgorithm) {
  switch (algorithm.name.toUpperCase()) {
    case "RSA-OAEP":
      const mdSize = /(\d+)$/.exec(algorithm.hash.name)![1];
      return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
    case "RSASSA-PKCS1-V1_5":
      return `RS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
    case "RSA-PSS":
      return `PS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
    case "RSA-PKCS1":
      return `RS1`;
    default:
      throw new core.OperationError("algorithm: Is not recognized");
  }
}
