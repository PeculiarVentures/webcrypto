import * as x509 from "@peculiar/x509";
import * as core from "@peculiar/webcrypto-core";
import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import { X509Certificate, X509CertificateRequest } from "../src";
import { crypto } from "./config";
import { isNSS } from "./helper";
import { Pkcs11RsaHashedKeyAlgorithm } from "../src/types";

const X509_RAW = Buffer.from("308203A830820290A003020102020900FEDCE3010FC948FF300D06092A864886F70D01010505003034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E61301E170D3037303632393135313330355A170D3237303632393135313330355A3034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E6130820122300D06092A864886F70D01010105000382010F003082010A0282010100C868F1C9D6D6B3347526821EECB4BEEA5CE126ED114761E1A27C16784021E4609E5AC863E1C4B19692FF186D6923E12B62F7DDE2362F9107B948CF0EEC79B62CE7344B700825A33C871B19F281070F389019D311FE86B4F2D15E1E1E96CD806CCE3B3193B6F2A0D0A995127DA59ACC6BC884568A33A9E722155316F0CC17EC575FE9A20A9809DEE35F9C6FDC48E3850B155AA6BA9FAC48E309B2F7F432DE5E34BE1C785D425BCE0E228F4D90D77D3218B30B2C6ABF8E3F141189200E7714B53D940887F7251ED5B26000EC6F2A28256E2A3E186317253F3E442016F626C825AE054AB4E7632CF38C16537E5CFB111A08C146629F22B8F1C28D69DCFA3A5806DF0203010001A381BC3081B9300F0603551D130101FF040530030101FF301D0603551D0E041604141AEDFE413990B42459BE01F252D545F65A39DC1130640603551D23045D305B80141AEDFE413990B42459BE01F252D545F65A39DC11A138A4363034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E61820900FEDCE3010FC948FF300E0603551D0F0101FF040403020106301106096086480186F8420101040403020007300D06092A864886F70D0101050500038201010085031E9271F642AFE1A3619EEBF3C00FF2A5D4DA95E6D6BE68363D7E6E1F4C8AEFD10F216D5EA55263CE12F8EF2ADA6FEB37FE1302C7CB3B3E226BDA612E7FD4723DDD30E11E4C40198C0FD79CD183307B9859DC7DC6B90C294CA133A2EB673A6584D396E2ED7645708FB52BDEF923D6496E3C14B5C69F351E50D0C18F6A70440262CBAE1D6841A7AA57E853AA07D206F6D514060B9103752C6C72B561959A0D8BB90DE7F5DF54CDDEE6D8D609089763E5C12EB0B74426C026C0AF55309E3BD5362A1904F45C1EFFCF2CB7FFD0FD874011D51123BB48C021A9A4282DFD15F8B04E2BF4305B21FC119134BE41EF7B9D9775FF9795C096582FEABB46D7BBE4D92E", "hex");
const X509_REQUEST_RAW = Buffer.from("308202BC308201A402003078310B3009060355040613025553311430120603550403130B6D792D737974652E6E6574311430120603550407130B53756E20416E746F6E696F311D301B060355040A13144D7920686F6D65206F7267616E697A6174696F6E310F300D06035504081306546573786173310D300B060355040B13044E6F6E6530820122300D06092A864886F70D01010105000382010F003082010A028201010092323A4560FF7FB0C022B6A9B72FE2F29F544AB8AAA4CFD1A1A71D9D0EB7B89CE85505DE15AC11785EDC5FFE45BC6B39E0688B7680FE1AFA42E36C50070AB52F01C1E86B139D10C9A0729CECDBF3CDF6FF538B6C2AE80498D6EAD5C90AC46131FD542C9EF0F400FCDA341E6CB61BA3C612D17A6CACB6415FBCFBF912E16BDCC3689C8C95BBE0C118884FC8A0F9597CB734B4C84A451FCB511BE6C7FDE0F45FE5B386CD32C675249012C3E2A0F18AB8DC880A960831943747E8C92F1972DDF8C18C59E07D59E98609B62B94FF88172D928D3B14FB8D66B4A6DE8B6DAE3AB6552F5CC8BFD1CF97DFB252EB551DBE2AF33826B3E26190ED48646556068196369DBB0203010001A000300D06092A864886F70D01010B050003820101001EBF4FF997C237C6001D4170BB8FCF64E3B3137D7746F4E08A3F884A127F235665EBBBB497FF8691AED2E1268728FFFF902ED577C86BDA86A59DFED036FEEAF7DE7B766F5AF1F7A08A7432C3B6F99C7223D0B76067A8D789B168F28E8FDEBD8D5F7EFFFE1F38EAAA0DB5BB1F861E9463B1299CC00E5329D24D8D0F049E650FEC4D62143651EBEDFF10795F0B1BC325EAC01951E2344FFD8850BF6A3FC1304FD4C4136CF27FE443A69B39F92F07A7F48BC8AC2AF3C9F3FD8236424DB838806F884677CCD122DE815C400E726A24B8A9E4D50FF75EFBCC2F8DCED7E88C4E727B1BAD84E0FA0F65A91D1D7FF54AF7279A33043ECAF205CDFACD05511E7E0641A970", "hex");
const X509_PEM = core.PemConverter.fromBufferSource(X509_RAW, "CERTIFICATE");
const X509_REQUEST_PEM = core.PemConverter.fromBufferSource(X509_REQUEST_RAW, "CERTIFICATE REQUEST");

(isNSS("CertStorage. NSS is readonly")
  ? context.skip
  : context)
  ("Certificate storage", () => {

    beforeEach(async () => {
      let keys = await crypto.certStorage.keys();
      if (keys.length) {
        await crypto.certStorage.clear();
      }

      keys = await crypto.certStorage.keys();
      assert.strictEqual(keys.length, 0);
    });

    context("indexOf", () => {
      const vector: {
        type: types.CryptoCertificateType;
        data: string | types.BufferSource;
        format: types.CryptoCertificateFormat;
      }[] = [
          { type: "x509", data: X509_RAW, format: "raw" },
          { type: "request", data: X509_REQUEST_RAW, format: "raw" },
          { type: "x509", data: X509_PEM, format: "pem" },
          { type: "request", data: X509_REQUEST_PEM, format: "pem" },
        ];
      vector.forEach((params) => {
        it(`${params.type} ${params.format}`, async () => {
          const cert = await crypto.certStorage.importCert(params.format, params.data, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
          const index = await crypto.certStorage.setItem(cert);
          const found = await crypto.certStorage.indexOf(cert);
          assert.strictEqual(found, null);
          const certByIndex = await crypto.certStorage.getItem(index, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
          assert.strictEqual(!!certByIndex, true, "Cannot get cert item from storage");
        });
      });
    });

    context("importCert", () => {

      it("x509", async () => {
        const item = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]) as X509Certificate;
        const json = item.toJSON();
        assert.strictEqual(json.publicKey.algorithm.name, "RSASSA-PKCS1-v1_5");
        assert.strictEqual((json.publicKey.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-256");
        assert.strictEqual(json.notBefore.toISOString(), "2007-06-29T15:13:05.000Z");
        assert.strictEqual(json.notAfter.toISOString(), "2027-06-29T15:13:05.000Z");
        assert.strictEqual(json.subjectName, "C=FR, O=Dhimyotis, CN=Certigna");
        assert.strictEqual(json.issuerName, "C=FR, O=Dhimyotis, CN=Certigna");
        assert.strictEqual(json.serialNumber, "00fedce3010fc948ff");
        assert.strictEqual(json.type, "x509");

        assert.strictEqual(item.label, "Certigna");
        assert.strictEqual(item.token, false);
        assert.strictEqual(item.sensitive, false);
      });

      it("x509 to token", async () => {
        const item = await crypto.certStorage.importCert(
          "raw",
          X509_RAW,
          {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
            token: true,
            label: "custom",
          } as types.RsaHashedImportParams,
          ["verify"]);

        assert.ok(item instanceof X509Certificate);
        assert.strictEqual(item.label, "custom");
        assert.strictEqual(item.token, true);
        assert.strictEqual(item.sensitive, false);
      });

      it("request", async () => {
        const item = await crypto.certStorage.importCert("raw", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" } as types.RsaHashedImportParams, ["verify"]) as X509CertificateRequest;
        const json = item.toJSON();
        assert.strictEqual(json.publicKey.algorithm.name, "RSASSA-PKCS1-v1_5");
        assert.strictEqual((json.publicKey.algorithm as Pkcs11RsaHashedKeyAlgorithm).hash.name, "SHA-384");
        assert.strictEqual(json.subjectName, "C=US, CN=my-syte.net, L=Sun Antonio, O=My home organization, ST=Tesxas, OU=None");
        assert.strictEqual(json.type, "request");

        assert.strictEqual(item.label, "X509 Request");
        assert.strictEqual(item.token, false);
        assert.strictEqual(item.sensitive, false);
      });

      it("request to token", async () => {
        const item = await crypto.certStorage.importCert("raw", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384", token: true, label: "custom" } as types.RsaHashedImportParams, ["verify"]) as X509CertificateRequest;

        assert.strictEqual(item.label, "custom");
        assert.strictEqual(item.token, true);
        assert.strictEqual(item.sensitive, false);
      });

      it("wrong type throws error", async () => {
        await assert.rejects(crypto.certStorage.importCert("wrong" as any, X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" } as types.RsaHashedImportParams, ["verify"]));
      });

    });

    context("set/get item", () => {

      it("x509", async () => {
        const x509 = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
        const index = await crypto.certStorage.setItem(x509);
        const x5092 = await crypto.certStorage.getItem(index);
        assert.strictEqual(!!x5092, true);
      });

      it("request", async () => {
        const request = await crypto.certStorage.importCert("raw", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
        const index = await crypto.certStorage.setItem(request);
        const request2 = await crypto.certStorage.getItem(index, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
        assert.strictEqual(!!request2, true);
      });

      it("null", async () => {
        const item = await crypto.certStorage.getItem("not exist");
        assert.strictEqual(item, null);
      });

      it("set wrong object", async () => {
        await assert.rejects(crypto.certStorage.setItem({} as any), Error);
      });

    });

    context("get value", () => {

      it("x509", async () => {
        const x509 = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
        const index = await crypto.certStorage.setItem(x509);
        const raw = await crypto.certStorage.getValue(index);
        assert.strictEqual(!!raw, true);
        assert.strictEqual(raw!.byteLength > 0, true);
      });

      it("request", async () => {
        const request = await crypto.certStorage.importCert("raw", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
        const index = await crypto.certStorage.setItem(request);
        const raw = await crypto.certStorage.getValue(index);
        assert.strictEqual(!!raw, true);
        assert.strictEqual(raw!.byteLength > 0, true);
      });

      it("null", async () => {
        const item = await crypto.certStorage.getItem("not exist");
        assert.strictEqual(item, null);
      });

      it("set wrong object", async () => {
        await assert.rejects(crypto.certStorage.setItem({} as any), Error);
      });

    });

    it("removeItem", async () => {
      let indexes = await crypto.certStorage.keys();
      assert.strictEqual(indexes.length, 0);

      const request = await crypto.certStorage.importCert("raw", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
      await crypto.certStorage.setItem(request);

      const x509 = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
      const x509Index = await crypto.certStorage.setItem(x509);

      indexes = await crypto.certStorage.keys();
      assert.strictEqual(indexes.length, 2);

      await crypto.certStorage.removeItem(x509Index);

      indexes = await crypto.certStorage.keys();
      assert.strictEqual(indexes.length, 1);
    });

    it("exportCert", async () => {
      const x509 = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as types.RsaHashedImportParams, ["verify"]);
      const raw = await crypto.certStorage.exportCert("raw", x509);
      assert.strictEqual(Buffer.from(raw).equals(X509_RAW), true);
    });

    it("test", async () => {
      const alg = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048
      };

      const keys = await crypto.subtle.generateKey(
        {
          ...alg,
          token: true,
        } as any,
        false,
        [
          "sign",
          "verify"
        ]);
      const keyIndex = await crypto.keyStorage.setItem(keys.privateKey);

      const cert = await x509.X509CertificateGenerator.createSelfSigned(
        {
          serialNumber: "01",
          name: "CN=Test",
          notBefore: new Date("2020/01/01"),
          notAfter: new Date("2020/01/02"),
          signingAlgorithm: alg,
          keys,
          extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            new x509.ExtendedKeyUsageExtension(
              ["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"],
              true
            ),
            new x509.KeyUsagesExtension(
              x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
              true
            )
          ]
        },
        crypto,
      );

      const fortifyCert = await crypto.certStorage.importCert(
        "raw",
        cert.rawData,
        {
          ...alg,
          token: true,
        },
        ["verify"]
      );
      const certIndex = await crypto.certStorage.setItem(fortifyCert);

      assert.strictEqual(keyIndex.split("-")[2], certIndex.split("-")[2]);
    });

  });
