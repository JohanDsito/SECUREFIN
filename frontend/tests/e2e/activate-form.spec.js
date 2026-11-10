import { expect, test } from "@playwright/test";
import { mailpit } from "./fixtures/mailpit.js";
import { totp } from "./fixtures/totp.js";

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
    await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("");
    // El token no queda en ningún almacenamiento del navegador
    const stored = await page.evaluate(() => JSON.stringify({ ...window.localStorage, ...window.sessionStorage }));
    expect(stored.includes(dummyToken)).toBe(false);
  });

  // Flujo real con el token del correo (FR-021, FR-022, FR-025). La cuenta pendiente la crea
  // `iam_bootstrap_admin` en el paso del CI anterior a Playwright; su correo llega en
  // SECUREFIN_E2E_ACTIVATION_EMAIL. Si falta, la prueba FALLA (U2). El token se consume aquí, el
  // mensaje se borra al final y ni el token ni la clave TOTP se imprimen ni se guardan.
  test("el envío consume el token real y activa la cuenta; un segundo uso falla; luego login y alta de MFA", async ({
    page,
  }) => {
    const email = process.env.SECUREFIN_E2E_ACTIVATION_EMAIL;
    expect(email, "SECUREFIN_E2E_ACTIVATION_EMAIL no está definida").toBeTruthy();
    const message = await mailpit.waitForMessage({ to: email, subject: "Activa tu cuenta" });
    try {
      const token = await mailpit.extractToken(message.ID);
      const password = "frase de activación e2e muy larga 2026";

      const activate = async () => {
        await page.goto("about:blank"); // carga completa: un cambio solo de fragmento no remonta la página
        await page.goto(`/activate#token=${token}`);
        await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("");
        await page.locator("#activate-password").fill(password);
        await page.locator("#activate-password-confirm").fill(password);
        const [response] = await Promise.all([
          page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/activate")),
          page.locator('#activate-form button[type="submit"]').click(),
        ]);
        return response.status();
      };

      expect(await activate()).toBe(204);
      await expect(page.getByText("Cuenta activada")).toBeVisible();
      expect(await activate()).toBe(400);
      await expect(page.getByRole("alert")).toContainText("no es válido o ha caducado");

      // Con la contraseña recién fijada, el Administrador entra y debe dar de alta el MFA (FR-022/025)
      await page.goto("/login");
      await page.locator("#login-email").fill(email);
      await page.locator("#login-password").fill(password);
      await page.locator('#login-form button[type="submit"]').click();
      await expect(page).toHaveURL(/\/login\/enroll$/);
      await page.locator('#enroll-start button[type="submit"]').click();
      const secret = (await page.locator("section code").innerText()).replace(/\s/g, "");
      await page.locator("#enroll-code").fill(totp(secret));
      await page.locator('#enroll-confirm button[type="submit"]').click();
      await expect(page.locator("#enroll-confirm")).toHaveCount(0); // se muestran los códigos de recuperación

      const session = await page.evaluate(async () => {
        const r = await fetch("/api/v1/auth/session", { credentials: "same-origin" });
        const body = await r.json().catch(() => ({}));
        return { status: r.status, role: body.user?.role, mfaEnabled: body.user?.mfa_enabled };
      });
      expect(session.status).toBe(200);
      expect(session.role).toBe("admin");
      expect(session.mfaEnabled).toBe(true);
      const stored = await page.evaluate(() => window.localStorage.length + window.sessionStorage.length);
      expect(stored).toBe(0);
    } finally {
      await mailpit.deleteMessages([message.ID]);
    }
  });
});

