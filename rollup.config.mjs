import typescript from "@rollup/plugin-typescript";
import pkg from "./package.json" with { type: "json" };

const startYear = 2019;
const currentYear = new Date().getFullYear();

const year
  = startYear === currentYear
    ? `${startYear}`
    : `${startYear}-${currentYear}`;

const banner = [
  "/**",
  ` * Copyright (c) ${year}, Peculiar Ventures`,
  " * SPDX-License-Identifier: MIT",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = [
  ...["node:crypto", "node:process", "node:buffer"],
  ...Object.keys(pkg.dependencies || {}),
];

export default [
  {
    input,
    plugins: [
      typescript({
        tsconfig: "./tsconfig.json",
        compilerOptions: { module: "ES2015" },
      }),
    ],
    external: [...external],
    output: [
      {
        banner,
        file: pkg.main,
        format: "cjs",
      },
      {
        banner,
        file: pkg.module,
        format: "es",
      },
    ],
  },
];
