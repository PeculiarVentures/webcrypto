import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import assert from "assert";
import * as asn from "../src/asn";

context("ASN", () => {

  context("RSA", () => {

    context("PrivateKey", () => {

      const bytes = Buffer.from("30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100f73bb19904c72d3a3a837425d734190a26760151bdd6e15c948b21996e64a713dcd4cf7c0ac722e4ee589ed82ba9a8ab4f17b9283c5145422a02f35f140b586a8adfeb6f40bfc223fc1c777d692126f94f8abfac63bc67f593c8cd027326f70888fb9ac20d573cf65f90f3825156a64c34d964e0b7aba3fffe38b9cd773beea3020301000102818100b52ba83c42b5165e7a2c843b8a9521d83f50f02c8f59dcb17424f48d33c94c6a10c45dfb3f06a87a6c72c28c148af20fff189a5572c5f763c1d781b265c4de975bcfaa303e365e0e78784d64ea8345d34c988018c8868edef526da3cd9a458306a3c9f37545a645490bacf8dd040aa7aab52b0cd38c4744ddc556a8b6dbeeb51024100fc66e213e9785a33417dc830534644fcb85ebc70c3b4f6d9957637e0142879e489ec5a0fc38acaa579100d1fff585d2ad13a7f4280985e47534a36a369eed0c9024100fac1f2aa44b2dd000febaf75b9dd554068b0c6f15b41fada8089d7a52c447980498dcd95546454f0860b8a7747f40c0e7362f5a1a935a61327e4fb6298d2460b02410085dbf68882e89e45d2b4e7a7a1728201d9b1fc947d668b0828393336f6d9e4936d06595944e665c4ce68d1dd2769f0b75591858e7a6ed4895545e5a652f721e9024100a7a03339c346d6198e8afcf5f3d39383c4f837656c9dc4b5802ba52e53534aed893df3ea194a20c5d0b5b2505e9733e00d1e60193b6613a8c68879cbc560fb550240169d53d05b35edae1a5b48351b7281e12ef2f281c8026d64ed3d884249788830fc23fa45d73adb3224fa26f65e51b4838572583135de65fb13d360d9e3e19c74", "hex");
      const json = {
        n: "APc7sZkExy06OoN0Jdc0GQomdgFRvdbhXJSLIZluZKcT3NTPfArHIuTuWJ7YK6moq08XuSg8UUVCKgLzXxQLWGqK3-tvQL_CI_wcd31pISb5T4q_rGO8Z_WTyM0Ccyb3CIj7msINVzz2X5DzglFWpkw02WTgt6uj__44uc13O-6j",
        e: "AQAB",
        d: "ALUrqDxCtRZeeiyEO4qVIdg_UPAsj1ncsXQk9I0zyUxqEMRd-z8GqHpscsKMFIryD_8YmlVyxfdjwdeBsmXE3pdbz6owPjZeDnh4TWTqg0XTTJiAGMiGjt71Jto82aRYMGo8nzdUWmRUkLrPjdBAqnqrUrDNOMR0TdxVaottvutR",
        p: "APxm4hPpeFozQX3IMFNGRPy4Xrxww7T22ZV2N-AUKHnkiexaD8OKyqV5EA0f_1hdKtE6f0KAmF5HU0o2o2nu0Mk",
        q: "APrB8qpEst0AD-uvdbndVUBosMbxW0H62oCJ16UsRHmASY3NlVRkVPCGC4p3R_QMDnNi9aGpNaYTJ-T7YpjSRgs",
        dp: "AIXb9oiC6J5F0rTnp6FyggHZsfyUfWaLCCg5Mzb22eSTbQZZWUTmZcTOaNHdJ2nwt1WRhY56btSJVUXlplL3Iek",
        dq: "AKegMznDRtYZjor89fPTk4PE-DdlbJ3EtYArpS5TU0rtiT3z6hlKIMXQtbJQXpcz4A0eYBk7ZhOoxoh5y8Vg-1U",
        qi: "Fp1T0Fs17a4aW0g1G3KB4S7y8oHIAm1k7T2IQkl4iDD8I_pF1zrbMiT6JvZeUbSDhXJYMTXeZfsT02DZ4-GcdA",
      };

      it("parse", () => {
        const keyInfo = AsnParser.parse(bytes, asn.PrivateKeyInfo);
        const key = AsnParser.parse(keyInfo.privateKey, asn.RsaPrivateKey);

        const jsonKey = JsonSerializer.toJSON(key);
        assert.deepEqual(jsonKey, json);
      });

      it("serialize", () => {
        const key = JsonParser.fromJSON(json, { targetSchema: asn.RsaPrivateKey });

        const keyInfo = new asn.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.privateKeyAlgorithm.parameters = null;
        keyInfo.privateKey = AsnSerializer.serialize(key);

        const asnKeyInfo = Buffer.from(AsnSerializer.serialize(keyInfo));
        assert.equal(asnKeyInfo.equals(bytes), true);
      });

    });

    context("PublicKey", () => {

      const bytes = Buffer.from("30819f300d06092a864886f70d010101050003818d0030818902818100f615b745314ffe4669255dfe68953184bb8e5db54eecd35b4c51ee899ce7e60aaf19cc765d924f94be93d6809ba506fab26b9f8ef0cf6ab2aec1942da222992f8dad2e621845f014f9e831a529665faf0a9b8ca97356a602ce8d17cd3469aafa2de82546773540fa480510d1906c78c87b81850c26fdaeccce37cd5fdeba7e050203010001", "hex");
      const json = {
        n: "APYVt0UxT_5GaSVd_miVMYS7jl21TuzTW0xR7omc5-YKrxnMdl2ST5S-k9aAm6UG-rJrn47wz2qyrsGULaIimS-NrS5iGEXwFPnoMaUpZl-vCpuMqXNWpgLOjRfNNGmq-i3oJUZ3NUD6SAUQ0ZBseMh7gYUMJv2uzM43zV_eun4F",
        e: "AQAB",
      };

      it("parse", () => {
        const keyInfo = AsnParser.parse(bytes, asn.PublicKeyInfo);
        const key = AsnParser.parse(keyInfo.publicKey, asn.RsaPublicKey);

        const jsonKey = JsonSerializer.toJSON(key);
        assert.deepEqual(jsonKey, json);
      });

      it("serialize", () => {
        const key = JsonParser.fromJSON(json, { targetSchema: asn.RsaPublicKey });

        const keyInfo = new asn.PublicKeyInfo();
        keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.publicKeyAlgorithm.parameters = null;
        keyInfo.publicKey = AsnSerializer.serialize(key);

        const asnKeyInfo = Buffer.from(AsnSerializer.serialize(keyInfo));
        assert.equal(asnKeyInfo.equals(bytes), true);
      });

    });

  });

  context("EC", () => {

    context("PrivateKey", () => {

      const bytes = Buffer.from("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420db0964fc2a963e9a2aef561f57db3556fa87e83ceb2e5f6dc84b00c18aa873e3a144034200043266c1386af7a0993b169393df1f7c4016e27fd48642e8d512c775b31c8f06722baef1310974a6c63aff2ef8832fba27f021f5ae2f2c6c2d56fde5be5ade78f5", "hex");
      const json = {
        d: "2wlk_CqWPpoq71YfV9s1VvqH6DzrLl9tyEsAwYqoc-M",
        x: "MmbBOGr3oJk7FpOT3x98QBbif9SGQujVEsd1sxyPBnI",
        y: "K67xMQl0psY6_y74gy-6J_Ah9a4vLGwtVv3lvlreePU",
      };

      it("parse", () => {
        const keyInfo = AsnParser.parse(bytes, asn.PrivateKeyInfo);
        const key = AsnParser.parse(keyInfo.privateKey, asn.EcPrivateKey);

        const jsonKey = JsonSerializer.toJSON(key);
        assert.deepEqual(jsonKey, json);
      });

      it("serialize", () => {
        const keyInfo = new asn.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
        keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(
          new asn.ObjectIdentifier("1.2.840.10045.3.1.7"),
        );
        const key = JsonParser.fromJSON(json, { targetSchema: asn.EcPrivateKey });
        keyInfo.privateKey = AsnSerializer.serialize(key);

        const asnKeyInfo = Buffer.from(AsnSerializer.serialize(keyInfo));
        assert.equal(asnKeyInfo.equals(bytes), true);
      });

    });

  });

});
