interface AlgorithmConverter {
    jwk2alg(alg: string): Algorithm;
    alg2jwk(alg: Algorithm): string;
}