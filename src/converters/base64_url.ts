import { IJsonConverter } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";

export const JsonBase64UrlConverter: IJsonConverter<Buffer, string> = {
  fromJSON: (value: string) => Buffer.from(Convert.FromBase64Url(value)),
  toJSON: (value: Buffer) => Convert.ToBase64Url(value),
};

export const JsonBase64UrlArrayBufferConverter: IJsonConverter<ArrayBuffer, string> = {
  fromJSON: (value: string) => Convert.FromBase64Url(value),
  toJSON: (value: ArrayBuffer) => Convert.ToBase64Url(new Uint8Array(value)),
};
