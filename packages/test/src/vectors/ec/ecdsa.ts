import * as types from "@peculiar/webcrypto-types";
import { Convert } from "pvtsutils";
import { ITestGenerateKeyAction, ITestParams } from "../../types";

export const ECDSA: ITestParams = {
  name: "ECDSA",
  actions: {
    generateKey: ["P-256", "P-384", "P-521", "K-256"].map((namedCurve) => {
      return {
        name: namedCurve,
        algorithm: {
          name: "ECDSA",
          namedCurve,
        } as types.EcKeyGenParams,
        extractable: false,
        keyUsages: ["sign", "verify"],
      } as ITestGenerateKeyAction;
    }),
    import: [
      {
        name: "JWK public key P-256",
        format: "jwk",
        data: {
          crv: "P-256",
          ext: true,
          key_ops: ["verify"],
          kty: "EC",
          x: "dJ9C3NyXDa3fMeZ477NWdp9W6faytA7A_U1ub-tyRcs",
          y: "aS0_VVe_SeIm8w5TBWjUEco7us6EJUMPKKJaIh36Lho",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-256",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "JWK public key P-384",
        format: "jwk",
        data: {
          crv: "P-384",
          ext: true,
          key_ops: ["verify"],
          kty: "EC",
          x: "eHlLZ4jnt_Drs-qoVxK-SZZvhNhi34jLCgyaEZ9XI6bdlK3y1ettm8K5SnLtDhWO",
          y: "qbr3pOOViYDQ2wWG-_9pwQ0S8cHV0LP-x9JO5dl-dsFYtbGix9YH7fRNOl8GkP-6",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-384",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "JWK public key P-521",
        format: "jwk",
        data: {
          crv: "P-521",
          ext: true,
          key_ops: ["verify"],
          kty: "EC",
          x: "Adqn62IVQX8LIauAXrUtxH05DHlRygKcsP9qWAnd9tfJvpaG7bzIs16WMEUe1V-f4AxbQJceU4xCP8dJppK_fzdC",
          y: "AEo3s1eExCOvpuBtBWnWlr7TuFhq_fMzqX9eqDHiy8qWl4I_koQtMePodrAc85mVrJAjvsa77Y3Ul3QtIWpXXBqa",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-521",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      //#region SPKI
      {
        name: "SPKI P-256",
        format: "spki",
        data: Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZMMqyfA16N6bvloFHmalk/SGMisr3zSXFZdR8F9UkaY7hF13hHiQtwp2YO+1zd7jwYi1Y7SMA9iUrC+ap2OCw=="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-256",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "SPKI P-384",
        format: "spki",
        data: Convert.FromBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8Kf5Wv21nksy0LuMlkMZv9sxTVAmzNWt81b6MVlYuzxl9D2/obwoVp86pTe4BM79gWWj8pfLc1XrjaIyMSrV8+05IejRLB3i4c0KTGA6QARGm3/AOm0MbTt6kMQF7drL"),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-384",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "SPKI P-521",
        format: "spki",
        data: Convert.FromBase64("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB+/g37ii0T5iLHCAaXcYRRoNpT0LhfeAr88OwQY4cUpQm1S9lkR0EVUtyuYrYsMB8FarhAZYsLtOiyhjl/Y5f+lQAZ6veWILhbDcbrSNhTPSp3wamAm8QT3EjPUkJlYjHefuAUBIYS9pl5FWjK1pI9fkYe3bdAemkjP1ccHVzqZU9sjg="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-521",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      //#endregion
      //#region RAW
      {
        name: "RAW P-256",
        format: "raw",
        data: Convert.FromBase64("BEehen4AavxgJkx5EPZpBeopzgZuY+1i3cMR9iYdZj+IY7/h98Q/GboC2BKS6lT0hEyt6y1DFFXj8ytuof4zXR4="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-256",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "RAW P-384",
        format: "raw",
        data: Convert.FromBase64("BGYoCpP3Qv4o0s2GWg5xFnasdkI8h6K/LeBm4TV+9HCsqnoXFUJDM5SDeZ0rcCAUUuaPJVn5sedPEKEGW80zmLM1rBOG2RzaBq+uhEJkLpibongnzMZNX2LB58wGJ05f2g=="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-384",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      {
        name: "RAW P-521",
        format: "raw",
        data: Convert.FromBase64("BABIiZ3f90HQsl4CYHt7Q1WnOIOs+dxeecfQrew/z+73yI/bUrMlmR3mOVARtvg7ZPX7h3lSSqzA1Vv6iv7bPYekcwDKQPeLJkem//H7zY8xtKY+YrYnLUVv6vPE9jyk2vYkj8QPxQRdeIT5bzY2BzTiTcLHDwi2+w2Eonkt7M+zb4G6xw=="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-521",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["verify"],
      },
      //#endregion
      //#region JWK Private key
      {
        name: "JWK private key P-256",
        format: "jwk",
        data: {
          crv: "P-256",
          d: "RIrfLaesGcEeNy7fOoVIkgMiImJOFw1Y44kdrtK_49I",
          ext: true,
          key_ops: ["sign"],
          kty: "EC",
          x: "wJls5KwIfRDxJEvyAlo3G84qNY0HjvsujyxDSMYAlm4",
          y: "I61bQbFgnzfDom68P86kRo98fTrV_9HLeqa4gYnGOdw",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-256",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      {
        name: "JWK private key P-384",
        format: "jwk",
        data: {
          crv: "P-384",
          d: "4YQRcOD-4LMLEr-qsRhQ1oq8hfPKa66BfGVUv3LUlsf2OU3aFG5FxabG5xFUoAE2",
          ext: true,
          key_ops: ["sign"],
          kty: "EC",
          x: "XKewC5QCVW9w-SFyZd3z1vlmCqbYYuJmoGRzKtjwkpYQD_RhNAc3ck29d_t0QmaT",
          y: "6oSrri3ry1_8c2NKM8aiaJcjwd146ITViezQ7-BpsE1-wDH18P1QkbmR3-Ho54We",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-384",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      {
        name: "JWK private key P-521",
        format: "jwk",
        data: {
          crv: "P-521",
          d: "AItxxufCXVzwPVePNe9Acy8HfbmYeUVkiEyFXdsYRnHxqgDpwucVnIJ44-ZWRpuWu5Ep5KVV3vY9Hp8nJfksi7z2",
          ext: true,
          key_ops: ["sign"],
          kty: "EC",
          x: "AJGuTezC-8F-d_0bBpS502OK0z63vo87Dw99a3NUm6gm5pQC1rwu7LcblGqFWOuFBZhsF8I6OFjYvsR-z3u7hhCA",
          y: "AFQT8BB9hBf7UwwBUV4im8bFJ7_MD0qOZMVetmdbooMjfec1q3wU5cSoy4LvCnWAaFqu5havUxwnAUuPUWGG_InR",
        },
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-521",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      //#endregion
      //#region PKCS8
      {
        name: "PKCS8 P-256",
        format: "pkcs8",
        data: Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVEY5OFo3J7g1BnSw/WEWykY/alrhNmpEBLy/7cNnuGhRANCAAQ4SFnMDGYc5kWv7D0gtgUj/Bzbu0B6Bq6XK1vqOo//2m8FS1D4kYKV4KDfFRWehKEtrMBjjkW6OZcM/n0qZ6Uw"),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-256",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      {
        name: "PKCS8 P-384",
        format: "pkcs8",
        data: Convert.FromBase64("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCY18ajGPCgLv4aF1UkkohMEaB5MU1MyfkuFQSQVDYHLWFTn8f9czce7aTIDjkCx0OhZANiAAR1fni8TC1N1NdXvx25kJyK3y3rpVVaAmA44Wm9jIFseGmSzm/EgmKOFclSzQdEpSC6jxi3olIJ4iYetjl36Ygfwed/xqrsiV6BUb/ny2mimzk3r0M9H6yvbEVQFd7rEAA="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-384",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      {
        name: "PKCS8 P-521",
        format: "pkcs8",
        data: Convert.FromBase64("MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAbHGkGfik5q0l+ZMI70dbpTGWeKy1+c3mG98wHmnpU+d2bArcYDOXcoqg5Ic/pnmtHvxmk+El33u3XogGONKPlouhgYkDgYYABAH16CoJzEx+Oncpeam6ysUG17y9ttNm5Eg8WqD+BJkP9ju3R22I5PVyYYYZ3ICc1IyDGxFCS7leO1N7tqQLaLi8NAEFTkwCy1G6AAK7LbSa1hNC2fUAaC9L8QJNUNJpjgYiXPDmEnaRNT1XXL00Bjo5iMpE2Ddc/Kp6ktTAo2jOMnfmow=="),
        algorithm: {
          name: "ECDSA",
          namedCurve: "P-521",
        } as types.EcKeyImportParams,
        extractable: true,
        keyUsages: ["sign"],
      },
      //#endregion
    ],
    sign: [
      {
        key: {
          privateKey: {
            format: "pkcs8",
            data: Convert.FromBase64("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsY5TBHM+9mLXGpFaPmrigl6+jl0XWzazxu1lbwb5KRahRANCAATqDP2L/xxSOlckG+j6oPHfzBE4WpmjA/YE9sP2rXpXW1qe9I/GJ7wjlOTXpqHUxQeBbps8jSvV+A7DzQqzjOst"),
            algorithm: {
              name: "ECDSA",
              namedCurve: "P-256",
            } as types.EcKeyImportParams,
            extractable: true,
            keyUsages: ["sign"],
          },
          publicKey: {
            format: "spki",
            data: Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6gz9i/8cUjpXJBvo+qDx38wROFqZowP2BPbD9q16V1tanvSPxie8I5Tk16ah1MUHgW6bPI0r1fgOw80Ks4zrLQ=="),
            algorithm: {
              name: "ECDSA",
              namedCurve: "P-256",
            } as types.EcKeyImportParams,
            extractable: true,
            keyUsages: ["verify"],
          },
        },
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        signature: Convert.FromBase64("gsTh0IcWfzj3hjjourRgzTIsNa+wcDEDlKnkEA4Jv8ygLF2IDIOXpCD7ocCGo7xlSMGTme78CyrPqWGSz95mZg=="),
        algorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        } as types.EcdsaParams,
      },
      {
        key: {
          privateKey: {
            format: "pkcs8",
            data: Convert.FromBase64("MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg0h6+W+/4eFVP+i79hrzYeiEJ6UrveFYhuhoXRW+g/LGhRANCAASiJU6MaFN5fshUv6X5rCf/RjLQ0nAXj06gBdo3ruYiKZf8daAcYImniAq81PjF0j6eTwCy4bYbkyfBQtrtCTKR"),
            algorithm: {
              name: "ECDSA",
              namedCurve: "K-256",
            } as types.EcKeyImportParams,
            extractable: true,
            keyUsages: ["sign"],
          },
          publicKey: {
            format: "spki",
            data: Convert.FromBase64("MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoiVOjGhTeX7IVL+l+awn/0Yy0NJwF49OoAXaN67mIimX/HWgHGCJp4gKvNT4xdI+nk8AsuG2G5MnwULa7QkykQ=="),
            algorithm: {
              name: "ECDSA",
              namedCurve: "K-256",
            } as types.EcKeyImportParams,
            extractable: true,
            keyUsages: ["verify"],
          },
        },
        data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        signature: Convert.FromBase64("lqUTZHqf9v9KcOCw5r5wR1sCt9RPA0ONVW6vqejpoALehd6vtAb+ybVrDEtyUDpBFw9UIRIW6GnXRrAz4KaO4Q=="),
        algorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        } as types.EcdsaParams,
      },
    ],
  },
};