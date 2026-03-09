import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  test: { globals: true },
  resolve: {
    alias: {
      "@x428/core": resolve(__dirname, "../core/src/index.ts"),
    },
  },
});
