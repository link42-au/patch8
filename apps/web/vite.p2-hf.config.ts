import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  publicDir: fileURLToPath(new URL("./static", import.meta.url)),
  build: {
    assetsInlineLimit: 0,
    emptyOutDir: true,
    outDir: fileURLToPath(new URL("./.p2-hf-proof", import.meta.url)),
    rollupOptions: {
      input: fileURLToPath(new URL("../../e2e/fixtures/p2-hf-browser-proof.ts", import.meta.url)),
      output: {
        assetFileNames: "assets/[name][extname]",
        entryFileNames: "proof.js",
      },
    },
  },
});
