import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, /api is proxied to the FastAPI backend on :8000
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: process.env.GATEWAY_URL ?? "http://localhost:8000", rewrite: (p) => p.replace(/^\/api/, "") } },
  },
});
