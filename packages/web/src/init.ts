import { nativeSubtle } from "./native";

declare const self: any;

function WrapFunction(subtle: any, name: string) {
    const fn = subtle[name];
    subtle[name] = function () {
        const args = arguments;
        return new Promise((resolve, reject) => {
            const op: any = fn.apply(subtle, args);
            op.oncomplete = (e: any) => {
                resolve(e.target.result);
            };
            op.onerror = (e: any) => {
                reject(`Error on running '${name}' function`);
            };
        });
    };
}

if (typeof self !== "undefined" && self["msCrypto"]) {
    WrapFunction(nativeSubtle, "generateKey");
    WrapFunction(nativeSubtle, "digest");
    WrapFunction(nativeSubtle, "sign");
    WrapFunction(nativeSubtle, "verify");
    WrapFunction(nativeSubtle, "encrypt");
    WrapFunction(nativeSubtle, "decrypt");
    WrapFunction(nativeSubtle, "importKey");
    WrapFunction(nativeSubtle, "exportKey");
    WrapFunction(nativeSubtle, "wrapKey");
    WrapFunction(nativeSubtle, "unwrapKey");
    WrapFunction(nativeSubtle, "deriveKey");
    WrapFunction(nativeSubtle, "deriveBits");
}

// fix: Math.imul for IE
if (!(Math as any).imul) {
    (Math as any).imul = function imul(a: number, b: number) {
        const ah = (a >>> 16) & 0xffff;
        const al = a & 0xffff;
        const bh = (b >>> 16) & 0xffff;
        const bl = b & 0xffff;
        return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
    };
}
