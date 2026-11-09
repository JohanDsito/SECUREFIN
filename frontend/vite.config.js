import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En desarrollo, Vite actúa como proxy de /api para conservar el MISMO ORIGEN que la API (R3):
// sin CORS y con la cookie de sesión enviada automáticamente.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: process.env.SECUREFIN_DEV_API ?? "https://securefin.local",
        changeOrigin: false,
        secure: false,
      },
    },
  },
  build: {
    sourcemap: false,
  },
});
