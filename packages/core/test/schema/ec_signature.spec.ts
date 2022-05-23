import * as assert from "assert";
import { Convert } from "pvtsutils";
import { AsnSerializer, AsnParser } from "@peculiar/asn1-schema";
import * as core from "@peculiar/webcrypto-core";

interface IEcSignatureTestVector {
  name: string;
  asn1: string;
  webCrypto: string;
}

context("ASN1", () => {

  context("ECDSA Signature Value", () => {

    const vectors: IEcSignatureTestVector[] = [
      {
        name: "P-256 #1",
        asn1: "3045022100d50b6b8b2f84ec9e8704fd7651eed26d1c9e60a773666ec122e135669eb435fe02206e08432c943aec0b3f223014731475277ff7a3840ac9dbd065aab04a540c9a28",
        webCrypto: "d50b6b8b2f84ec9e8704fd7651eed26d1c9e60a773666ec122e135669eb435fe6e08432c943aec0b3f223014731475277ff7a3840ac9dbd065aab04a540c9a28",
      },
      {
        name: "P-256 #2",
        asn1: "304402205cce26e35066669ee84acad747d39abe8b882a569004a6d4c1992d66b3b26caf0220791e998153331d52a3b972b77fb1b6e2caf3cb7b8cdc60fd486443819ff08208",
        webCrypto: "5cce26e35066669ee84acad747d39abe8b882a569004a6d4c1992d66b3b26caf791e998153331d52a3b972b77fb1b6e2caf3cb7b8cdc60fd486443819ff08208",
      },
      {
        name: "P-384 #1",
        asn1: "3066023100f56792d36a7bd7836e94947343c308f528b5eb9327c468d6cab1b40498824f6f165d5335eabfcc553403b00579a5b68c023100a9daad0d1fbf5903eb1b42cca280f1a39baa33a2b32c19523c3967f7c9a3d23a9fdaab39b6bfedd82ba12abbedda24b1",
        webCrypto: "f56792d36a7bd7836e94947343c308f528b5eb9327c468d6cab1b40498824f6f165d5335eabfcc553403b00579a5b68ca9daad0d1fbf5903eb1b42cca280f1a39baa33a2b32c19523c3967f7c9a3d23a9fdaab39b6bfedd82ba12abbedda24b1",
      },
      {
        name: "P-384 #2",
        asn1: "3064023020f5cacedfe6d32ef782027f3cd58dddc6d27ab92cef562eca2d9e7089b450673246141a41c3d0d14f61ffa012a2a100023034cdcb83981758c58bcd92666393a85799b4f5a073347833f22d301aae0bb415cfaf2c6eade9fde00d79365ab6ca93da",
        webCrypto: "20f5cacedfe6d32ef782027f3cd58dddc6d27ab92cef562eca2d9e7089b450673246141a41c3d0d14f61ffa012a2a10034cdcb83981758c58bcd92666393a85799b4f5a073347833f22d301aae0bb415cfaf2c6eade9fde00d79365ab6ca93da",
      },
      {
        name: "P-521 #1",
        asn1: "30818702417767d9adbc3994e25c9c0328ab591f0ca6d9b24152c5f692ae4c62efa0b9317a0a26fcaf83ce87d337e8c3945fe8281e738f25ead6999c9521a2c2724f06bdc0e8024201a0aa892238ee98902b4a25c5efb940677cfd11a43df382f633f32d1c6b751ccd00fedfa106c298f652292b16dc1964521a04e42e0c8eaeb368222c6e94b42f325d",
        webCrypto: "007767d9adbc3994e25c9c0328ab591f0ca6d9b24152c5f692ae4c62efa0b9317a0a26fcaf83ce87d337e8c3945fe8281e738f25ead6999c9521a2c2724f06bdc0e801a0aa892238ee98902b4a25c5efb940677cfd11a43df382f633f32d1c6b751ccd00fedfa106c298f652292b16dc1964521a04e42e0c8eaeb368222c6e94b42f325d",
      },
      {
        name: "P-521 #2",
        asn1: "3081880242011e0ff3c825b1133ef2779bbffd05374b17eeeff37444108a4c480b881ba3f3f426c3344fb1173dcec305f3e49408965092f946e609dfb845efaaaa25a43c679b0c024201a1366cd7b11efe7a41418cf83156bfdac56bb6253fd018a23974fc182948f3a84d5241922f09b8a60c4366f58b2b86461886515bd79872bb55e9840c412db766da",
        webCrypto: "011e0ff3c825b1133ef2779bbffd05374b17eeeff37444108a4c480b881ba3f3f426c3344fb1173dcec305f3e49408965092f946e609dfb845efaaaa25a43c679b0c01a1366cd7b11efe7a41418cf83156bfdac56bb6253fd018a23974fc182948f3a84d5241922f09b8a60c4366f58b2b86461886515bd79872bb55e9840c412db766da",
      },
    ];

    context("From WebCrypto to DER", () => {
      vectors.forEach((vector) => {
        it(vector.name, () => {
          const value = core.asn1.EcDsaSignature.fromWebCryptoSignature(Convert.FromHex(vector.webCrypto));
          const der = AsnSerializer.serialize(value);
          assert.strictEqual(Convert.ToHex(der), vector.asn1);
        });
      });
    });

    context("From DER to WebCrypto", () => {
      vectors.forEach((vector) => {
        it(vector.name, () => {
          const value = AsnParser.parse(Convert.FromHex(vector.asn1), core.asn1.EcDsaSignature);
          const signature = value.toWebCryptoSignature();
          assert.strictEqual(Convert.ToHex(signature), vector.webCrypto);
        });
      });
    });

  });

});
