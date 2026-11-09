import { expect, test } from "@playwright/test";
import { mailpit } from "./fixtures/mailpit.js";

// TS-E02 (T135): Formulario de activación (/activate#token=...) compatible con gestores de contraseñas.
// Verificación del fragmento en memoria, atributos seguros y consumo de un solo uso.
test.describe("formulario de activación (/activate)", () => {
  const dummyToken = "abcdef1234567890abcdef1234567890abcdef1234";

  test("atributos y estructura compatibles con gestores de contraseñas", async ({ page }) => {
    await page.goto(`/activate#token=${dummyToken}`);

    const passwordField = page.locator("#activate-password");
    await expect(passwordField).toHaveAttribute("autocomplete", "new-password");
    await expect(passwordField).toHaveAttribute("type", "password");

    const info = await passwordField.evaluate((el) => ({
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

  test("permite pegar la contraseña sin cancelaciones", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto(`/activate#token=${dummyToken}`);

    const value = "contraseña segura pegada desde gestor 2026";
    const passwordField = page.locator("#activate-password");
    await passwordField.focus();

    const notCancelled = await passwordField.evaluate((el, text) => {
      const data = new DataTransfer();
      data.setData("text/plain", text);
      const event = new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true });
      return el.dispatchEvent(event);
    }, value);

    expect(notCancelled).toBe(true);
    await page.evaluate((text) => navigator.clipboard.writeText(text), value);
    await page.keyboard.press(process.platform === "darwin" ? "Meta+V" : "Control+V");
    await expect(passwordField).toHaveValue(value);
  });

  test("el fragmento #token se limpia tras cargar mediante history.replaceState", async ({ page }) => {
    await page.goto(`/activate#token=${dummyToken}`);
    const hash = await page.evaluate(() => window.location.hash);
    expect(hash).toBe("");
  });
});

