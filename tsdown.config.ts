import { defineConfig } from "tsdown";

const startYear = 2019;
const currentYear = new Date().getFullYear();
const year = startYear === currentYear ? `${startYear}` : `${startYear}-${currentYear}`;

const banner = ["/**", ` * Copyright (c) ${year}, Peculiar Ventures`, " * SPDX-License-Identifier: MIT", " */"].join("\n");

export default defineConfig({
  entry: "src/index.ts",
  // ESM only. CommonJS consumers load it through require(esm) on Node ^20.19 / >=22.12.
  format: ["esm"],
  // Node.js only: the mechanisms are built on node:crypto.
  platform: "node",
  dts: true,
  clean: true,
  // Emit one file per source module. Bundled multi-entry declarations leave
  // rolldown's `__exportAll` namespace helper in shared declaration chunks
  // (see rolldown/tsdown#1051); unbundled output keeps it in its own module.
  unbundle: true,
  // Keep .js/.d.ts output names (package.json is "type": "module")
  // instead of fixed .mjs/.d.mts extensions.
  fixedExtension: false,
  deps: {
    neverBundle: true,
  },
  exports: {
    legacy: true,
  },
  outputOptions: {
    // Drop TSDoc from the JS output; docs ship in the .d.ts files. Keep
    // @__PURE__ annotations so bundlers can tree-shake.
    comments: { legal: true, annotation: true, jsdoc: false },
  },
  banner,
  outDir: "build",
  tsconfig: "tsconfig.json",
  attw: {
    level: "error",
    profile: "esm-only",
  },
});
