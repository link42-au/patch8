import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  publicDir: fileURLToPath(new URL("./static", import.meta.url)),
  build: {
    assetsInlineLimit: 0,
    emptyOutDir: true,
    outDir: fileURLToPath(new URL("./.p2-proof", import.meta.url)),
    rollupOptions: {
      input: fileURLToPath(new URL("./src/lib/dataset/browser-proof.ts", import.meta.url)),
      output: {
        assetFileNames: "assets/[name][extname]",
        entryFileNames: "proof.js",
      },
    },
  },
});
