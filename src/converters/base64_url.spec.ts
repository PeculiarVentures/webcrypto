import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { JsonBase64UrlConverter } from "./base64_url";

const fromJSON = (value: string) => JsonBase64UrlConverter.fromJSON(value, undefined);
const toJSON = (value: Buffer) => JsonBase64UrlConverter.toJSON(value, undefined);

// Same results as 1.7.1 (@peculiar/utils 2): unpadded base64url only.
describe("JsonBase64UrlConverter", () => {
  it("decodes unpadded base64url", () => {
    expect(fromJSON("-_8")).toEqual(Buffer.from([0xfb, 0xff]));
    expect(fromJSON("")).toEqual(Buffer.alloc(0));
  });

  it("ignores whitespace", () => {
    expect(fromJSON("-_\n8")).toEqual(Buffer.from([0xfb, 0xff]));
  });

  it.each([
    ["padding", "-_8="],
    ["base64 alphabet", "+/8"],
    ["invalid character", "-_*"],
  ])("rejects %s", (_name, value) => {
    expect(() => fromJSON(value)).toThrow(TypeError);
  });

  it("encodes without padding", () => {
    expect(toJSON(Buffer.from([0xfb, 0xff]))).toBe("-_8");
  });
});
