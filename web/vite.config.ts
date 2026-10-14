import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built files are served by the platform API under /app (no CDN, CSP script-src 'self').
export default defineConfig({
  plugins: [react()],
  base: "/app/",
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
  // Dev: the API and its sign-in page run on :8000; the session cookie is per host, not port.
  server: {
    port: 5173,
    host: "127.0.0.1",
    proxy: { "/app/api": "http://127.0.0.1:8000", "/ui": "http://127.0.0.1:8000" },
  },
});
