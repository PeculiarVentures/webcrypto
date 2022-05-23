import { IJsonConverter } from "@peculiar/json-schema";
import { Convert, BufferSourceConverter } from "pvtsutils";

export const JsonBase64UrlArrayBufferConverter: IJsonConverter<ArrayBuffer, string> = {
  fromJSON: (value: string) => Convert.FromBase64Url(value),
  toJSON: (value: ArrayBuffer) => Convert.ToBase64Url(new Uint8Array(value)),
};
