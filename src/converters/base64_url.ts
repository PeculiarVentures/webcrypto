import { Buffer } from "node:buffer";
import { IJsonConverter } from "@peculiar/json-schema";
import { convert } from "@peculiar/utils";

export const JsonBase64UrlConverter: IJsonConverter<Buffer, string> = {
  fromJSON: (value: string) => Buffer.from(convert.decode("base64url", value)),
  toJSON: (value: Buffer) => convert.encode("base64url", value),
};
