declare namespace EllipticJS {
    class EC {
        constructor();
        genKeyPair(): EllipticKeyPair;
        keyFromPrivate(hexString: string, encoding: "hex" | "der"): EllipticKeyPair;
        keyFromPrivate(hexString: string | number[] | ArrayBuffer): EllipticKeyPair;
        keyFromPublic(hexString: string | number[] | ArrayBuffer, enc?: string): EllipticKeyPair;
    }

    class BN {
        toArray(): number[];
        toBytes(): ArrayBuffer;
    }

    class Point {
        x: BN;
        y: BN;
    }

    type EncodeFormat = "hex" | "der";

    class EllipticKeyPair {
        getSecret(enc?: string): any;
        getPrivate(enc?: string): any;
        getPublic(enc: "der"): number[];
        getPublic(enc: "hex"): string;
        getPublic(): Point;
        getPublic(enc?: EncodeFormat): string | number[] | Point;
        priv?: any;
        pub?: Point;
        sign(data: number[]): any;
        verify(data: number[], hexSignature: string): boolean;
        verify(data: number[], signature: object): boolean;
        derive(point: any): BN;
    }

    class EllipticModule {
        version: string;
        utils: {
            assert: Function;
            toArray: Function;
            zero2: Function;
            toHex: Function;
            encode: Function;
            getNAF: Function;
            getJSF: Function;
            cachedProperty: Function;
            parseBytes: Function;
            intFromLE: Function;
        };
        hmacDRBG: Function;
        curves: {
            PresetCurve: any;
            p192: any;
            p224: any;
            p256: any;
            p384: any;
            p521: any;
            curve25519: any;
            ed25519: any;
            secp256k1: any;
        };
        ec: typeof EC;
        eddsa: any;
    }
}

declare const elliptic: {
    ec: (namedCurve: string) => EllipticJS.EC;
};

declare module "elliptic" {

    const version: string;
    const utils: {
        assert: Function;
        toArray: Function;
        zero2: Function;
        toHex: Function;
        encode: Function;
        getNAF: Function;
        getJSF: Function;
        cachedProperty: Function;
        parseBytes: Function;
        intFromLE: Function;
    };
    const hmacDRBG: Function;
    const curves: {
        PresetCurve: any;
        p192: any;
        p224: any;
        p256: any;
        p384: any;
        p521: any;
        curve25519: any;
        ed25519: any;
        secp256k1: any;
    };
    function ec(namedCurve: string): EllipticJS.EC;
    const eddsa: any;

}
