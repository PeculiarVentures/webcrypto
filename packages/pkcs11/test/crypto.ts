import * as types from "@peculiar/webcrypto-types";
import * as assert from "assert";
import * as graphene from "graphene-pk11";
import { ITemplateBuilder, ITemplateBuildParameters, ITemplate, Pkcs11AesKeyAlgorithm } from "../src/types";
import { config, crypto } from "./config";

context("Crypto", () => {

  it("get random values", () => {
    const buf = new Uint8Array(16);
    const check = Buffer.from(buf).toString("base64");
    assert.notStrictEqual(Buffer.from(crypto.getRandomValues(buf)).toString("base64"), check, "Has no random values");
  });

  it("get random values with large buffer", () => {
    const buf = new Uint8Array(65600);
    assert.throws(() => {
      crypto.getRandomValues(buf);
    }, Error);
  });

  it("reset", () => {
    const currentHandle = crypto.session.handle.toString("hex");
    crypto.reset();

    if (config.pin) {
      crypto.login(config.pin);
    }
    const newHandle = crypto.session.handle.toString("hex");
    assert.strictEqual(currentHandle !== newHandle, true, "handle of session wasn't changed");
  });

  context("custom template builder", () => {
    class CustomTemplateBuilder implements ITemplateBuilder {

      build(params: ITemplateBuildParameters): ITemplate {
        return {
          label: "CustomTemplate",
          token: false,
          sensitive: false,
          class: graphene.ObjectClass.SECRET_KEY,
          encrypt: true,
          decrypt: false,
          sign: false,
          verify: false,
          wrap: false,
          unwrap: false,
          derive: false,
        };
      }

    }

    const templateBuilder = crypto.templateBuilder;
    before(() => {
      crypto.templateBuilder = new CustomTemplateBuilder();
    });

    after(() => {
      crypto.templateBuilder = templateBuilder;
    });

    it("create AES-CBC", async () => {
      const key = await crypto.subtle.generateKey({ name: "AES-CBC", length: 128 } as types.AesKeyGenParams, true, ["encrypt", "decrypt"]);
      assert.strictEqual((key.algorithm as Pkcs11AesKeyAlgorithm).label, "CustomTemplate");
      assert.deepStrictEqual(key.usages, ["encrypt"]);
    });
  });

});
