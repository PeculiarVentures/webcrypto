import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestParams, ITestGenerateKeyAction } from "../../types";

export const RSAESPKCS1: ITestParams = {
  name: "RSAES-PKCS1-v1_5",
  actions: {
    generateKey: [
      {
        algorithm: {
          name: "RSAES-PKCS1-v1_5",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 1024,
        } as types.RsaKeyGenParams,
        extractable: false,
        keyUsages: ["encrypt", "decrypt"],
      } as ITestGenerateKeyAction,
    ],
    encrypt: [
      {
        algorithm: {
          name: "RSAES-PKCS1-v1_5",
        } as types.Algorithm,
        data: Convert.FromHex("01435e62ad3ec4850720e34f8cab620e203749f2315b203d"),
        encData: Convert.FromHex("76e5ea6e1df52471454f790923f60e2baa7adf5017fe0a36c0af3e32f6390d570e1d592375ba6035fdf4ffa70764b797ab54d0ab1efe89cf31d7fc98240a4d08c2476b7eb4c2d92355b8bf60e3897c3fcbfe09f20c7b159d9a9c4a6b2ce5021dd313e492afa762c24930f97f03a429f7b2b1e1d6088651d60e323835807c6fefe7952f74e5da29e8e327ea46e69a0a6684272f022bf18ec602ffcd10a62666b35a51ec7c7d101096f663ddfa0924a86bdbcde0433b4f71dc42bfd9facf329558026f8667f1a71c3365e09843a12339d8aaf31987b0d800e53fd0835e990096cb145e278153faf1188cd5713c6fcd289cb77d80515e1d200139b8ccac4d3bcebc"),
        key: {
          publicKey: {
            format: "jwk",
            algorithm: { name: "RSAES-PKCS1-v1_5" } as types.Algorithm,
            data: {
              alg: "RS1",
              e: "AQAB",
              ext: true,
              key_ops: ["encrypt"],
              kty: "RSA",
              n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
            },
            extractable: true,
            keyUsages: ["encrypt"],
          },
          privateKey: {
            format: "jwk",
            algorithm: { name: "RSAES-PKCS1-v1_5" } as types.Algorithm,
            data: {
              kty: "RSA",
              alg: "RS1",
              key_ops: ["decrypt"],
              ext: true,
              n: "xr8ELXq5dGFycys8jrc8vVPkWl2GzuRgyOxATtjcNIy5MD7j1XVsUH62VVdIVUUGt0IQ7K288ij3gkIPcIkRO6GmV0vbQAqHrjSHYUAtKQXbIgNRIuJGZvO5AXsxSo1X-tfhOxe140pseOkaehz1bGduhdcYWNR3xLmp7i-GQTRDo-v6CQXtFvSUwG_EIOXnl1trN2Q1Yw4wA1dbtY9FDz69uH-dEWTx7BFCAXVTQMjNe7BTvgGeQcX7XZIw5e2pd0pXjdIgb0xMgziwmc5bbABrGlhK7TmKqA47RlWzY_Lcj7VcTUfMfh7YKKichGTUbqxlgsRTma_e-0-vgDEz6w",
              e: "AQAB",
              d: "kZ2IoQ3G7UcshMdL8kC85vadW7wktldLtkqqf1qSVIo6cOfTJCWJe5yrWPG_VIJjfkeQgOh2hHKRjcV67HfwwWEZr-IrPMu6R1_DRPSxYdohiNUnUEi7TlkJ1tT882OF74rWQeaIZIS13wzjUk7_XjKWHsfO1d6t9dwWbiYx1nj4syQCcUrvHIgVXCfL85Tyu3NHqpxOdbzRb2OLmkv5ciHFExm4ai98xAgsEXbNvZQeSOOfKNsiCb-NjBXLYrbaDIsakAEV75893JubfeD51UHn7dPT8M8MmKEvrTOKCscShf01scTDHfx_hiOXK3XG4tVx9l2YGEkt3xCedljocQ",
              p: "_dWMJ57SECcBbOjPRCvT97ypDyw9ydvnSZXTsn9c7ScxvUxBk6-wuMtgsLI8OWkhZGDBLyVrn-I3RMAN-A5QI_adoGdK7fq5lFWmQYvb1u1xUaGEInVFsM3BW7RBBF8N7OzHwULEQLTXb4jkpgwyCynsX0OEbVVvVerqrcr7osM",
              q: "yHEjuQe9TNo-leMrL6cu-yDPfA85M8xQuBM59Cwz06-ggBRi9EOpbV-CrejGUbVlE9QmKGqIBT8C3NVBQwybzlgUihgIpnVgkb01lLEf13ohQ_GWV1mS8ybznjMgaVtVF5Lva4WixIDlXbOu4svVQpkr-KRpKvEMUCTsX-Sxx7k",
              dp: "jMP4TaCN7dczuyoAh1Wm3yQIvRlTyrXgtbYZCEwJRJsPwmKfmz87Sb-_hz3QmCXtFrVxbKvb23agH8hB9uY5GziQgXvG2eLJN7Gn2YGuEKrsxNBFbraKR1pTeH-l7r6oAlPtEwfrvdaMApZv9oWc2wQMyWev8NIIRCVar7Z5hfE",
              dq: "wi2g3sJZp9cRpGEDWFHM2KnrdxLEZqK7W-f8T8h2mM9eXFXjmyDlRLivP0zuuv9QoUn3gVXa2cI2QrsxUwQm-Fop47Hux1uUpvs2qgqBf1yoV0r2Sz7Sdk442fxLnOVG5OSKno5Cpbz89q54cOvoeHEswN59p4UHWai7eRZzB7k",
              qi: "k9hlEyvZCWj8Fvxrknj5WHgaLrSqaVku3PVod2wUJox3aZ8vUsGmmD27lfiWwVKNRmgxLiazY40pLPu07SEmlJgF8QjzDb33k5Pcn9wRuezcCi-53LBRK6-EptZ-UjEINBlM_Cx_WOuxs7P77pwcCo2NV76ilxP5PP_34SUZ0ts",
            },
            extractable: true,
            keyUsages: ["decrypt"],
          },
        },
      },
    ],
  },
};