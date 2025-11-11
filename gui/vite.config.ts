import path from "path";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const api = `http://localhost:${process.env.PORT || 31337}`;

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
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
