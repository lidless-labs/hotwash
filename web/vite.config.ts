import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          flow: ["react-flow-renderer"],
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5177,
    proxy: {
      "/api": "http://localhost:8001",
    },
  },
});
