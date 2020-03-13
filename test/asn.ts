import assert from "assert";
import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as asn from "../src/asn";

context("ASN", () => {

  context("RSA", () => {

    context("PrivateKey", () => {

      const bytes = Buffer.from("308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100faa3f76e5daf5dc288a54b7a99d7c7a9437581a184d80bb1aaf54cdfe245b28f52edb4db4888199e78ce993407bfd93c8102231b173eca09d44bb127c152b2e7f3a806852ed1dc323a1a33a5fecc0217ea98ddeb7068c14ffbbbd14a7904b3657a663ab76d2d88b10db77bc1b22e8881e58665508af0c31da225d08f3b07ad05bd8cf4d25943bffd3bb57d4266582276089e126db030d8ef04e0c30eeb65c325558d98bfc43b2b0c52212f3294d3ad7a91fa2ec2e838b2e73a4db616ec6aad5592dfc046f7e3589741fa0f4662fcf4ffca767611475f05272b3ddbd09b757b56f0293089d39e2cdd35722cd69ea00b3181e6e7c5e531f6608db3da31ce82afad02030100010282010025698d3901adf8125e204244822b45e7dba4721da07d393da375ab2c6e139644338e3ce5508dd43925f23cc719f306a3b3e414466a715a6a1e30d0384d70a138e3536ce9bb63e2f8f2584fe652c2b3fb4aeed78d59c1a13d65a792e5896becb5549066ea53572d24b495f358a5d6b154a664a9c1dc8374b47b2c26d6026b3265b1d6e4448bd2253ce467ae99017c53af1fb085cdd5c8dc3cc66941beaa480295e907a936776f49e5e619d5e2e89e5a1bf220121c965b08b658d669464a4d0eb414efe11c8fa20987fae0758542ec69a9d335b01a78b8770b499272105629b4e81f04065644928f0b01bfb0294fbeb0e0e4e3ad6129d356fce820d35171126b1702818100fe042d914643ad84d8e5a0d0c3c7dc9b35ac60d96ef9305e74ead8419a1937c3a4d5b6b2d589f818ab0cfa4f6ee12fbeb85f7c117ba4eb489b31f0eecac4f8368b52b3339043a3160fa3535e1e45634947b582438149b062b73029bd2279793154153da0e120c48fe71c466783e6537ea9157d776bedd272e08fe4e961fe14ff02818100fc990a2846cf6c0f38ad798855a81f2386795425523f99a8660968be450564d97d62b58533bb9e65c36d56d28480b39bbbfaf7ddfdb8b08aa080740038b1786e659dfb342cdf197bcb8c40af1719814c734cec50b3e915cf927b6eb8e880d4073ab2d6c1e106c78e5add9042476f78edfb76d2d7ef5e1ae4c33f51c558691f5302818100b4a329f86e5c40700182427b534eb4add75c6f3f10b0ba59e191041a9ac82624c5fa88c2e2220c41169ad3025bda5d86a63c98d121f964ac2c593679c9ce8aa8d7290770babdaea348999ff6855658c5caede3e5b7723cb1e68da490f08c2bc80d8051642fd48a93bf09177413935e7aeb28f22153aa3b0720749397f7eca4e702818067661215589f11c1cd569d98245014a70b25e13f01c30d1834e4871ed3cc18733af34c10c1937c8c7589ed6f7153e9b1c72a3d8a7e90ba9b9485e07632bedae87dea44692031171268c8f9b572843b3c5b3a52c5da4f80611eba2e21bcf2f7581a3c18d2f6553b1cd7af389d18f6d58ebd4fef90fae80fa433145959aa0e260702818045ef370e79be4352cae716a92244f37f0b4a5133442b49de4a8bc5342d40a00eed284dcb5061d6dcde01baa12fde1ee965f66acabf58bd08d2f78c8f5f00a9156242ea971940611c8f9892335e48e211d2667aa0c5186af712cbab48802f2fc37488316e72d8dfd28a9e311e962fba79324e14d61a61d4afc4646da76dc650ae", "hex");
      const json = {
        d: "JWmNOQGt-BJeIEJEgitF59ukch2gfTk9o3WrLG4TlkQzjjzlUI3UOSXyPMcZ8wajs-QURmpxWmoeMNA4TXChOONTbOm7Y-L48lhP5lLCs_tK7teNWcGhPWWnkuWJa-y1VJBm6lNXLSS0lfNYpdaxVKZkqcHcg3S0eywm1gJrMmWx1uREi9IlPORnrpkBfFOvH7CFzdXI3DzGaUG-qkgClekHqTZ3b0nl5hnV4uieWhvyIBIcllsItljWaUZKTQ60FO_hHI-iCYf64HWFQuxpqdM1sBp4uHcLSZJyEFYptOgfBAZWRJKPCwG_sClPvrDg5OOtYSnTVvzoINNRcRJrFw",
        dp: "tKMp-G5cQHABgkJ7U060rddcbz8QsLpZ4ZEEGprIJiTF-ojC4iIMQRaa0wJb2l2GpjyY0SH5ZKwsWTZ5yc6KqNcpB3C6va6jSJmf9oVWWMXK7ePlt3I8seaNpJDwjCvIDYBRZC_UipO_CRd0E5Neeuso8iFTqjsHIHSTl_fspOc",
        dq: "Z2YSFVifEcHNVp2YJFAUpwsl4T8Bww0YNOSHHtPMGHM680wQwZN8jHWJ7W9xU-mxxyo9in6QupuUheB2Mr7a6H3qRGkgMRcSaMj5tXKEOzxbOlLF2k-AYR66LiG88vdYGjwY0vZVOxzXrzidGPbVjr1P75D66A-kMxRZWaoOJgc",
        e: "AQAB",
        n: "-qP3bl2vXcKIpUt6mdfHqUN1gaGE2AuxqvVM3-JFso9S7bTbSIgZnnjOmTQHv9k8gQIjGxc-ygnUS7EnwVKy5_OoBoUu0dwyOhozpf7MAhfqmN3rcGjBT_u70Up5BLNlemY6t20tiLENt3vBsi6IgeWGZVCK8MMdoiXQjzsHrQW9jPTSWUO__Tu1fUJmWCJ2CJ4SbbAw2O8E4MMO62XDJVWNmL_EOysMUiEvMpTTrXqR-i7C6Diy5zpNthbsaq1Vkt_ARvfjWJdB-g9GYvz0_8p2dhFHXwUnKz3b0Jt1e1bwKTCJ054s3TVyLNaeoAsxgebnxeUx9mCNs9oxzoKvrQ",
        p: "_gQtkUZDrYTY5aDQw8fcmzWsYNlu-TBedOrYQZoZN8Ok1bay1Yn4GKsM-k9u4S--uF98EXuk60ibMfDuysT4NotSszOQQ6MWD6NTXh5FY0lHtYJDgUmwYrcwKb0ieXkxVBU9oOEgxI_nHEZng-ZTfqkVfXdr7dJy4I_k6WH-FP8",
        q: "_JkKKEbPbA84rXmIVagfI4Z5VCVSP5moZglovkUFZNl9YrWFM7ueZcNtVtKEgLObu_r33f24sIqggHQAOLF4bmWd-zQs3xl7y4xArxcZgUxzTOxQs-kVz5J7brjogNQHOrLWweEGx45a3ZBCR2947ft20tfvXhrkwz9RxVhpH1M",
        qi: "Re83Dnm-Q1LK5xapIkTzfwtKUTNEK0neSovFNC1AoA7tKE3LUGHW3N4BuqEv3h7pZfZqyr9YvQjS94yPXwCpFWJC6pcZQGEcj5iSM15I4hHSZnqgxRhq9xLLq0iALy_DdIgxbnLY39KKnjEeli-6eTJOFNYaYdSvxGRtp23GUK4",
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

      const bytes = Buffer.from("30820122300d06092a864886f70d01010105000382010f003082010a0282010100faa3f76e5daf5dc288a54b7a99d7c7a9437581a184d80bb1aaf54cdfe245b28f52edb4db4888199e78ce993407bfd93c8102231b173eca09d44bb127c152b2e7f3a806852ed1dc323a1a33a5fecc0217ea98ddeb7068c14ffbbbd14a7904b3657a663ab76d2d88b10db77bc1b22e8881e58665508af0c31da225d08f3b07ad05bd8cf4d25943bffd3bb57d4266582276089e126db030d8ef04e0c30eeb65c325558d98bfc43b2b0c52212f3294d3ad7a91fa2ec2e838b2e73a4db616ec6aad5592dfc046f7e3589741fa0f4662fcf4ffca767611475f05272b3ddbd09b757b56f0293089d39e2cdd35722cd69ea00b3181e6e7c5e531f6608db3da31ce82afad0203010001", "hex");
      const json = {
        n: "-qP3bl2vXcKIpUt6mdfHqUN1gaGE2AuxqvVM3-JFso9S7bTbSIgZnnjOmTQHv9k8gQIjGxc-ygnUS7EnwVKy5_OoBoUu0dwyOhozpf7MAhfqmN3rcGjBT_u70Up5BLNlemY6t20tiLENt3vBsi6IgeWGZVCK8MMdoiXQjzsHrQW9jPTSWUO__Tu1fUJmWCJ2CJ4SbbAw2O8E4MMO62XDJVWNmL_EOysMUiEvMpTTrXqR-i7C6Diy5zpNthbsaq1Vkt_ARvfjWJdB-g9GYvz0_8p2dhFHXwUnKz3b0Jt1e1bwKTCJ054s3TVyLNaeoAsxgebnxeUx9mCNs9oxzoKvrQ",
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
