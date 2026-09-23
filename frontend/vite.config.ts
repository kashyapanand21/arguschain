import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The backend runs on :3000. Proxying through the dev server means the browser
// only ever talks to localhost:5173, which is also the domain the SIWE message
// names — keeping the signed domain and the real origin identical.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: "http://localhost:3000", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
});
