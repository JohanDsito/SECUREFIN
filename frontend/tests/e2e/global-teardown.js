import fs from "node:fs";

// Borra la salida temporal de Playwright (U1): no debe sobrevivir ningún artefacto de prueba.
export default async function globalTeardown() {
  const dir = process.env.SECUREFIN_E2E_OUTPUT_DIR;
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
}
