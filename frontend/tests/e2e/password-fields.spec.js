import { expect, test } from "@playwright/test";

// TS-E01 (T133): formularios de US1 compatibles con gestores de contraseñas (FR-005; escenario 4 de US1).
// Solo /register y /login: /activate lo prueba T135 (US4) y /reset, T136 (US7). Sin trazas, vídeos ni
// capturas (playwright.config.js); ninguna aserción incluye contraseñas.
const FORMS = [
  { path: "/register", email: "#register-email", password: "#register-password", passwordAutocomplete: "new-password" },
  { path: "/login", email: "#login-email", password: "#login-password", passwordAutocomplete: "current-password" },
];

for (const form of FORMS) {
  test.describe(`formulario ${form.path}`, () => {
    test("atributos autocomplete correctos", async ({ page }) => {
      await page.goto(form.path);
      await expect(page.locator(form.email)).toHaveAttribute("autocomplete", "username");
      await expect(page.locator(form.password)).toHaveAttribute("autocomplete", form.passwordAutocomplete);
      await expect(page.locator(form.password)).toHaveAttribute("type", "password");
    });

    test("estructura compatible con gestores de contraseñas", async ({ page }) => {
      await page.goto(form.path);
      const password = page.locator(form.password);
      const info = await password.evaluate((el) => ({
        inForm: el.closest("form") !== null,
        hasSubmit: el.closest("form")?.querySelector('button[type="submit"]') !== null,
        name: el.getAttribute("name"),
        id: el.id,
        readOnly: el.readOnly,
        autocompleteOff: el.getAttribute("autocomplete") === "off",
        maxLength: el.maxLength,
      }));
      expect(info.inForm).toBe(true);
      expect(info.hasSubmit).toBe(true);
      expect(info.name).toBeTruthy();
      expect(info.id).toBeTruthy();
      expect(info.readOnly).toBe(false);
      expect(info.autocompleteOff).toBe(false);
      expect(info.maxLength === -1 || info.maxLength >= 128).toBe(true);
    });

    test("se puede pegar la contraseña", async ({ page, context }) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await page.goto(form.path);
      const value = "frase de prueba pegada desde un gestor";
      const password = page.locator(form.password);
      await password.focus();
      const notCancelled = await password.evaluate((el, text) => {
        const data = new DataTransfer();
        data.setData("text/plain", text);
        const event = new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true });
        return el.dispatchEvent(event);
      }, value);
      expect(notCancelled).toBe(true); // ningún manejador llama a preventDefault()
      await page.evaluate((text) => navigator.clipboard.writeText(text), value);
      await page.keyboard.press(process.platform === "darwin" ? "Meta+V" : "Control+V");
      await expect(password).toHaveValue(value);
    });
  });
}
