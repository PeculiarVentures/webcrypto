import { Buffer } from "buffer";
import { IJsonConverter } from "@peculiar/json-schema";
import { Convert } from "pvtsutils";

export const JsonBase64UrlConverter: IJsonConverter<Buffer, string> = {
  fromJSON: (value: string) => Buffer.from(Convert.FromBase64Url(value)),
  toJSON: (value: Buffer) => Convert.ToBase64Url(value),
};
