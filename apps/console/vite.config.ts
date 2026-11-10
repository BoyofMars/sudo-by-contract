import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

const client = fileURLToPath(new URL("../../packages/sbc-client/src/index.ts", import.meta.url));

export default defineConfig({
  base: "./",
  plugins: [react()],
  resolve: {
    alias: { "@sbc/client": client },
  },
  server: {
    port: 5180,
    fs: { allow: ["../.."] },
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
