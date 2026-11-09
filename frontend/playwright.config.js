import { defineConfig } from "@playwright/test";
import os from "node:os";
import path from "node:path";

// Protección de tokens en E2E (corrección U1): sin trazas, vídeos ni capturas, reporter `list`
// sin informes HTML/JSON y salida en un directorio temporal fuera del repositorio que se borra
// en globalTeardown. Las pruebas abren URLs con #token=… que nunca deben quedar en artefactos.
const outputDir = path.join(os.tmpdir(), `securefin-e2e-${process.pid}`);
process.env.SECUREFIN_E2E_OUTPUT_DIR = outputDir;

export default defineConfig({
  testDir: "./tests/e2e",
  outputDir,
  reporter: [["list"]],
  retries: 0,
  globalTeardown: "./tests/e2e/global-teardown.js",
  use: {
    baseURL: process.env.SECUREFIN_STACK_URL ?? "https://securefin.local",
    // El navegador del runner no confía en la CA efímera del laboratorio; la validez de TLS se
    // verifica aparte (T121, TS-S21). El fixture de Mailpit sí valida la CA con NODE_EXTRA_CA_CERTS.
    ignoreHTTPSErrors: true,
    trace: "off",
    video: "off",
    screenshot: "off",
  },
});
