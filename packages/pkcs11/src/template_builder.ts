import * as graphene from "graphene-pk11";
import { BufferSourceConverter } from "pvtsutils";
import * as types from "./types";

export class TemplateBuilder implements types.ITemplateBuilder {

  public build(params: types.ITemplateBuildParameters): types.ITemplate {
    const { attributes, action, type } = params;
    const template: types.ITemplate = {
      token: !!attributes.token,
    };

    if (action === "copy") {
      if (type === "private") {
        if (attributes.token) {
          // TODO SafeNET 5110 token requires CKA_SENSITIVE:true and CKA_EXTRACTABLE:false
          //      Those values must be set in C_GenerateKeyPair, or C_CopyObject, or C_CreateObject
          // Object.assign<types.ITemplate, types.ITemplate>(template, {
          //   sensitive: true,
          // });
        }
      }
    } else {
      if (attributes.label) {
        template.label = attributes.label
      }
      if (attributes.id) {
        template.id = Buffer.from(BufferSourceConverter.toArrayBuffer(attributes.id));
      }

      const sign = attributes.usages?.includes("sign");
      const verify = attributes.usages?.includes("verify");
      const wrap = attributes.usages?.includes("wrapKey");
      const unwrap = attributes.usages?.includes("unwrapKey");
      const encrypt = unwrap || attributes.usages?.includes("encrypt");
      const decrypt = wrap || attributes.usages?.includes("decrypt");
      const derive = attributes.usages?.includes("deriveBits") || attributes.usages?.includes("deriveKey");

      switch (type) {
        case "private":
          Object.assign<types.ITemplate, types.ITemplate>(template, {
            class: graphene.ObjectClass.PRIVATE_KEY,
            sensitive: !!attributes.sensitive,
            private: true,
            extractable: !!attributes.extractable,
            derive,
            sign,
            decrypt,
            unwrap,
          });
          break;
        case "public":
          Object.assign<types.ITemplate, types.ITemplate>(template, {
            token: !!attributes.token,
            class: graphene.ObjectClass.PUBLIC_KEY,
            private: false,
            derive,
            verify,
            encrypt,
            wrap,
          });
          break;
        case "secret":
          Object.assign<types.ITemplate, types.ITemplate>(template, {
            class: graphene.ObjectClass.SECRET_KEY,
            sensitive: !!attributes.sensitive,
            extractable: !!attributes.extractable,
            derive,
            sign,
            verify,
            decrypt,
            encrypt,
            unwrap,
            wrap,
          });
          break;
        case "request":
          if (template.id) {
            template.objectId = template.id;
            delete template.id;
          }
          Object.assign<types.ITemplate, types.ITemplate>(template, {
            class: graphene.ObjectClass.DATA,
            application: "webcrypto-p11",
            private: false,
          });
          break;
        case "x509":
          Object.assign<types.ITemplate, types.ITemplate>(template, {
            class: graphene.ObjectClass.CERTIFICATE,
            certType: graphene.CertificateType.X_509,
            private: false,
          });
          break;
      }
    }

    return template;
  }

}
