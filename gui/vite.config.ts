import fs from "fs";
import path from "path";

import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const api = `http://localhost:${process.env.PORT || 31337}`;

const R2_WASM_PATH = path.join(
  import.meta.dirname,
  "node_modules",
  "@frida",
  "react-use-r2",
  "dist",
  "r2.wasm",
);

const r2WasmPlugin: Plugin = {
  name: "r2-wasm-plugin",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.originalUrl?.endsWith("/r2.wasm")) {
        const data = fs.readFileSync(R2_WASM_PATH);
        res.setHeader("Content-Length", data.length);
        res.setHeader("Content-Type", "application/wasm");
        res.end(data, "binary");
        return;
      }
      next();
    });
  },
  async writeBundle(options) {
    const destPath = path.join(options.dir || "dist", "r2.wasm");
    await fs.promises.copyFile(R2_WASM_PATH, destPath);
  },
};

// https://vite.dev/config/
export default defineConfig({
  server: {
    proxy: {
      "/api": {
        target: api,
        changeOrigin: true,
        secure: false,
      },
      "/socket.io/": {
        target: api,
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  plugins: [react(), tailwindcss(), r2WasmPlugin],
  assetsInclude: "**/*.wasm",
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "@shared/schema": path.resolve(__dirname, "..", "shared", "schema.d.ts"),
    },
  },
});
