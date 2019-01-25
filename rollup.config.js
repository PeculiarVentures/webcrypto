import typescript from "rollup-plugin-typescript";

const pkg = require("./package.json");

const banner = [pkg.banner || "", ""];

export default {
    input: "src/index.ts",
    plugins: [
        typescript({ typescript: require("typescript"), target: "esnext", removeComments: true }),
    ],
    external: ["crypto", ...Object.keys(pkg.dependencies)],
    output: [
        {
            banner: banner.join("\n"),
            file: pkg.main,
            format: "cjs",
        }
    ]
};