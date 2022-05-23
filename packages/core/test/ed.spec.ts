import { AsnConvert, AsnSerializer } from "@peculiar/asn1-schema";
import * as assert from "assert";
import { Convert } from "pvtsutils";
import * as schema from "packages/core/src/schema";

context("ED", () => {

  context("asn", () => {

    it("spki - jwk", () => {
      const pem = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

      const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), schema.PublicKeyInfo);
      const key = new schema.EdPublicKey(keyInfo.publicKey);
      const jwk = key.toJSON();

      const key2 = new schema.EdPublicKey();
      key2.fromJSON(jwk);
      assert.strictEqual(
        Convert.ToBase64(AsnSerializer.serialize(key2)),
        Convert.ToBase64(AsnSerializer.serialize(key)),
      );
    });

    context("pkcs8 -jwk", () => {

      it("without public key", () => {
        const pem = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";

        const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), schema.OneAsymmetricKey);
        assert.strictEqual(keyInfo.publicKey, undefined);
        const key = AsnConvert.parse(keyInfo.privateKey, schema.EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new schema.EdPrivateKey();
        key2.fromJSON(jwk);
        assert.strictEqual(
          Convert.ToBase64(AsnSerializer.serialize(key2)),
          Convert.ToBase64(AsnSerializer.serialize(key)),
        );
      });

      it("with public key", () => {
        const pem = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

        const keyInfo = AsnConvert.parse(Convert.FromBase64(pem), schema.OneAsymmetricKey);
        assert.ok(keyInfo.publicKey);
        const key = AsnConvert.parse(keyInfo.privateKey, schema.EdPrivateKey);
        const jwk = key.toJSON();

        const key2 = new schema.EdPrivateKey();
        key2.fromJSON(jwk);
        assert.strictEqual(
          Convert.ToBase64(AsnSerializer.serialize(key2)),
          Convert.ToBase64(AsnSerializer.serialize(key)),
        );
      });

    });

  });

});
