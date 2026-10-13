import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    port: 5173,
    // The key is added by this dev proxy (and by nginx in Docker); it never enters the browser bundle.
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL ?? "http://127.0.0.1:8000",
        changeOrigin: true,
        headers: process.env.DEV_API_KEY ? { "X-API-Key": process.env.DEV_API_KEY } : {},
      },
    },
  },
});
