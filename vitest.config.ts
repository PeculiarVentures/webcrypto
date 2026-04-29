// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { tsconfigPaths: true },
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.spec.ts", "test/**/*.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov", "text-summary"],
      include: ["src/**/*.ts", "!src/**/*.spec.ts"],
      exclude: ["**/*.d.ts"],
    },
  },
});
