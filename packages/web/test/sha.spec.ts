import * as types from "@peculiar/webcrypto-types";
import * as pvtsutils from "pvtsutils";
import { testCrypto } from "./utils";
import { webCrypto } from "./utils";

context("SHA", () => {

  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

  testCrypto(webCrypto, [
    {
      name: "SHA",
      actions: {
        digest: [
          {
            name: "SHA-1",
            algorithm: "SHA-1",
            data,
            hash: pvtsutils.Convert.FromBase64("6JrVqWMcPv3e1+Psznm00P7c4b8="),
          },
          {
            name: "SHA-256",
            algorithm: "SHA-256",
            data,
            hash: pvtsutils.Convert.FromBase64("monGjExeKLjEpVZ2c9Ri//UV20YRb5kAYk0JxHT1k/s="),
          },
          {
            name: "SHA-384",
            skip: typeof module !== "undefined", // skip for nodejs
            algorithm: "SHA-384",
            data,
            hash: pvtsutils.Convert.FromBase64("E9WqubQC9JnxffIniWwf0soI91o5z0Kbvk+s/32Fi3z28kAh+Fcne7Hgy1nnW4rR"),
          },
          {
            name: "SHA-512",
            algorithm: "SHA-512",
            data,
            hash: pvtsutils.Convert.FromBase64("OtPzaXlFDU9TNmJE7PEBD0+RIdaIgoX/FBBP1a3thdSKoXG/HjOhEmAvkrenCIsph4kBL7h7kFYyEkGhn7dOCw=="),
          },
        ],
      },
    },
    {
      name: "SHAKE",
      actions: {
        digest: [
          {
            name: "shake128 default",
            algorithm: "shake128",
            data,
            hash: pvtsutils.Convert.FromHex("83eb77696796112190033833050fbd57"),
          },
          {
            name: "shake128 128 byte length",
            algorithm: {
              name: "shake128",
              length: 128,
            } as types.ShakeParams,
            data,
            hash: pvtsutils.Convert.FromHex("83eb77696796112190033833050fbd57c6b678d762053e931c978d9c1586b5c4c09fb0cfa40f68094cd6520bec7c21ac47072053243ba42283322a4aeebe23f7675f96c7fa22a9f8b4d63b0b6634dca3b6a6138870c1afc3ada61a3bd816d576b4783101205a1ddf364210c05d6c72ef861936828c446e3c3584d0607d53e46e"),
          },
          {
            name: "shake256 default",
            algorithm: "shake256",
            data,
            hash: pvtsutils.Convert.FromHex("5719c4fb8351b11f091815582a33cb5f7caba174f2dd7429d3298383e67af205"),
          },
          {
            name: "shake256 256 byte length",
            algorithm: {
              name: "shake256",
              length: 256,
            } as types.ShakeParams,
            data,
            hash: pvtsutils.Convert.FromHex("5719c4fb8351b11f091815582a33cb5f7caba174f2dd7429d3298383e67af20588ce4967a3867f6d7fde600336b14188dba8f14b999970223395e53de9d09285ee861c1817a1e2c66c894d230944ec16e0f65b605fb7ee707b114702905037df89dfa9910dd850e1b789eb6efbfc5002a335d9270a9bb66d409df65d8b0755e5081918f8d0d9e49f4aca83d5a097bde0ccd5cecbe2724f22e5aab61fb43cd22f108aa5db02cb122c84a860037a4bb292b3f2a6a1193c642c61ab83f9e6310c896fdf3487c23863c9c7b7cb806ffeff44bc21fbd2c4e65ee6c76bf4336e4a11008368ae9264eab5f728bb2924f3410dd1d821b0d8a18b30a7420ad469f1bfd04d"),
          },
        ],
      },
    },
  ]);

});
