import { expect, test } from "@playwright/test";

// T093: interfaz de administración y de reinicio de MFA con la API SIMULADA (page.route).
// Solo prueba el comportamiento de la interfaz: estados de carga, confirmaciones, envíos dobles,
// errores del servidor y que nada se guarda en el almacenamiento del navegador. La autorización
// real (401/403/409, BOLA, MFA) la prueban las suites del backend contra la API de verdad.
// Sin trazas, vídeos ni capturas (playwright.config.js).

const ME = {
  id: "u-admin",
  email: "admin@lab.securefin.local",
  name: "Admin",
  role: "admin",
  mfa_enabled: true,
  mfa_required: true,
};
const user = (id, email, extra = {}) => ({
  id,
  email,
  name: email.split("@")[0],
  role: "client",
  status: "active",
  mfa_enabled: false,
  created_at: "2026-11-01T10:00:00Z",
  last_login_at: null,
  ...extra,
});
const USERS = [
  user("u-admin", ME.email, { role: "admin", mfa_enabled: true }),
  user("u-ana", "ana@lab.securefin.local"),
];
const SESSION = { "GET /auth/session": { json: { user: ME, session: {} } } };
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function mockApi(page, handlers) {
  const calls = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const key = `${request.method()} ${path}`;
    calls.push({ key, body: request.postDataJSON?.() ?? null });
    if (key === "GET /auth/csrf") return route.fulfill({ status: 204 });
    const handler = handlers[key];
    if (!handler) return route.fulfill({ status: 404, json: { error: { code: "not_found", message: "-" } } });
    const result = typeof handler === "function" ? await handler(request) : handler;
    if (result.status === 204) return route.fulfill({ status: 204 });
    return route.fulfill({ status: result.status ?? 200, json: result.json });
  });
  return calls;
}

async function expectNoBrowserStorage(page) {
  const sizes = await page.evaluate(() => [window.localStorage.length, window.sessionStorage.length]);
  expect(sizes).toEqual([0, 0]);
}

test.describe("admin/Users", () => {
  test("muestra la carga, el listado y ninguna acción sobre la propia cuenta", async ({ page }) => {
    await mockApi(page, {
      ...SESSION,
      "GET /admin/users": async () => {
        await delay(400);
        return { json: { results: USERS, next: null, previous: null } };
      },
    });
    await page.goto("/admin/users");
    await expect(page.getByRole("status")).toContainText("Cargando");
    const self = page.getByRole("row", { name: /admin@lab/ });
    await expect(self).toContainText("Tu cuenta");
    await expect(self.getByRole("button")).toHaveCount(0);
    await expect(page.getByRole("row", { name: /ana@lab/ }).getByRole("button", { name: "Desactivar" })).toBeVisible();
  });

  test("desactivar exige confirmación, bloquea envíos dobles y muestra el error del servidor", async ({ page }) => {
    const calls = await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { json: { results: USERS, next: null, previous: null } },
      "POST /admin/users/u-ana/deactivate": async () => {
        await delay(400);
        return { status: 409, json: { error: { code: "invalid_state", message: "-" } } };
      },
    });
    await page.goto("/admin/users");
    const row = page.getByRole("row", { name: /ana@lab/ });

    await row.getByRole("button", { name: "Desactivar" }).click();
    expect(calls.filter((c) => c.key.endsWith("/deactivate"))).toHaveLength(0); // aún no se ha enviado
    await row.getByRole("button", { name: "Confirmar" }).click();

    await expect(page.getByRole("button", { name: "Crear y enviar activación" })).toBeDisabled(); // en curso
    await expect(page.getByRole("alert")).toContainText("estado actual de la cuenta");
    expect(calls.filter((c) => c.key.endsWith("/deactivate"))).toHaveLength(1);
  });

  test("cancelar la confirmación no envía nada", async ({ page }) => {
    const calls = await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { json: { results: USERS, next: null, previous: null } },
    });
    await page.goto("/admin/users");
    const row = page.getByRole("row", { name: /ana@lab/ });
    await row.getByRole("combobox").selectOption("auditor");
    await row.getByRole("button", { name: "Cambiar rol" }).click();
    await expect(row.getByRole("group")).toContainText("Se cerrarán sus sesiones");
    await row.getByRole("button", { name: "Cancelar" }).click();
    expect(calls.filter((c) => c.key.includes("/role"))).toHaveLength(0);
  });

  test("cambio de rol confirmado envía exactamente el rol elegido", async ({ page }) => {
    const calls = await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { json: { results: USERS, next: null, previous: null } },
      "PATCH /admin/users/u-ana/role": { json: { id: "u-ana", role: "auditor", status: "active" } },
    });
    await page.goto("/admin/users");
    const row = page.getByRole("row", { name: /ana@lab/ });
    await row.getByRole("combobox").selectOption("auditor");
    await row.getByRole("button", { name: "Cambiar rol" }).click();
    await row.getByRole("button", { name: "Confirmar" }).click();
    await expect(page.getByRole("status")).toContainText("Rol cambiado");
    expect(calls.find((c) => c.key === "PATCH /admin/users/u-ana/role").body).toEqual({ role: "auditor" });
  });

  test("errores de validación por campo al crear una cuenta", async ({ page }) => {
    await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { json: { results: USERS, next: null, previous: null } },
      "POST /admin/users": {
        status: 400,
        json: { error: { code: "validation_error", message: "-", fields: { name: ["Nombre no válido."] } } },
      },
    });
    await page.goto("/admin/users");
    await page.getByLabel("Correo (ficticio)").fill("nuevo@lab.securefin.local");
    await page.getByLabel("Nombre").fill("Nuevo");
    await page.getByRole("button", { name: "Crear y enviar activación" }).click();
    await expect(page.getByRole("alert")).toContainText("Nombre no válido.");
    await expect(page.getByLabel("Correo (ficticio)")).toHaveValue("nuevo@lab.securefin.local"); // no se pierde
  });

  test("sin sesión (401) ofrece iniciar sesión; sin permiso (403) lo indica", async ({ page }) => {
    await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { status: 401, json: { error: { code: "auth_failed", message: "-" } } },
    });
    await page.goto("/admin/users");
    await expect(page.getByRole("alert").getByRole("link", { name: "Iniciar sesión" })).toBeVisible();

    await page.unrouteAll();
    await mockApi(page, {
      ...SESSION,
      "GET /admin/users": { status: 403, json: { error: { code: "forbidden", message: "-" } } },
    });
    await page.goto("/admin/users");
    await expect(page.getByRole("alert")).toContainText("No tienes permiso");
  });
});

test.describe("admin/MfaResets", () => {
  const CASE = {
    case_id: "c-1",
    target_user_id: "u-ana",
    target_email: "ana@lab.securefin.local",
    requested_at: "2026-11-10T10:00:00Z",
  };

  test("abrir un caso pide confirmar la verificación fuera de banda y envía el canal elegido", async ({ page }) => {
    const calls = await mockApi(page, {
      "GET /admin/mfa-resets": { json: { results: [{ ...CASE, status: "requested" }] } },
      "POST /admin/mfa-resets/c-1/open": { json: { status: "pending_verification" } },
    });
    await page.goto("/admin/mfa-resets");
    await page.getByLabel("Canal fuera de banda").selectOption("course_channel");
    await page.getByRole("button", { name: "Abrir caso" }).click();
    await expect(page.getByRole("group")).toContainText("Canal oficial del curso");
    expect(calls.filter((c) => c.key.endsWith("/open"))).toHaveLength(0);
    await page.getByRole("button", { name: "Sí, abrir caso" }).click();
    await expect(page.getByRole("status")).toContainText("Caso abierto");
    expect(calls.find((c) => c.key.endsWith("/open")).body).toEqual({ request_channel: "course_channel" });
  });

  test("una autorización fallida muestra el error y borra los códigos del formulario", async ({ page }) => {
    const calls = await mockApi(page, {
      "GET /admin/mfa-resets": { json: { results: [{ ...CASE, status: "pending_verification" }] } },
      "POST /admin/mfa-resets/c-1/authorize": {
        status: 400,
        json: { error: { code: "verification_failed", message: "-" } },
      },
    });
    await page.goto("/admin/mfa-resets?status=pending_verification");
    await page.getByLabel("Estado").selectOption("pending_verification");
    await page.getByLabel("Código que te lee el titular").fill("ABCD2345");
    await page.getByLabel("Tu código TOTP actual").fill("123456");
    await page.getByLabel(/Confirmo que recibí el código/).check();
    await page.getByRole("button", { name: "Autorizar reinicio" }).click();

    await expect(page.getByRole("alert")).toContainText("Al tercer fallo el caso se cancela");
    await expect(page.getByLabel("Código que te lee el titular")).toHaveValue("");
    await expect(page.getByLabel("Tu código TOTP actual")).toHaveValue("");
    expect(calls.find((c) => c.key.endsWith("/authorize")).body).toEqual({
      verification_code: "ABCD2345",
      admin_totp_code: "123456",
      channel_confirmed: true,
    });
    await expectNoBrowserStorage(page);
  });

  test("cancelar un caso exige confirmación", async ({ page }) => {
    const calls = await mockApi(page, {
      "GET /admin/mfa-resets": { json: { results: [{ ...CASE, status: "requested" }] } },
      "POST /admin/mfa-resets/c-1/cancel": { status: 204 },
    });
    await page.goto("/admin/mfa-resets");
    await page.getByRole("button", { name: "Cancelar caso" }).click();
    await page.getByRole("button", { name: "No" }).click();
    expect(calls.filter((c) => c.key.endsWith("/cancel"))).toHaveLength(0);
    await page.getByRole("button", { name: "Cancelar caso" }).click();
    await page.getByRole("button", { name: "Sí, cancelar el caso" }).click();
    await expect(page.getByRole("status")).toContainText("Caso cancelado");
  });
});

test.describe("MfaStep: Perdí mi dispositivo y mis códigos", () => {
  test("pide confirmación, envía la solicitud y explica los siguientes pasos", async ({ page }) => {
    const calls = await mockApi(page, {
      "POST /auth/login/mfa-reset-request": { status: 202, json: { status: "mfa_reset_requested" } },
    });
    await page.goto("/login/mfa");
    await page.getByRole("button", { name: "Perdí mi dispositivo y mis códigos" }).click();
    await expect(page.getByRole("group")).toContainText("Tu contraseña no cambia");
    expect(calls.filter((c) => c.key.includes("mfa-reset-request"))).toHaveLength(0);
    await page.getByRole("button", { name: "Sí, solicitar reinicio" }).click();
    await expect(page.getByRole("status")).toContainText("Un Administrador contactará contigo");
    await expectNoBrowserStorage(page);
  });

  test("al superar el límite (429) informa del máximo de solicitudes", async ({ page }) => {
    await mockApi(page, {
      "POST /auth/login/mfa-reset-request": { status: 429, json: { error: { code: "throttled", message: "-" } } },
    });
    await page.goto("/login/mfa");
    await page.getByRole("button", { name: "Perdí mi dispositivo y mis códigos" }).click();
    await page.getByRole("button", { name: "Sí, solicitar reinicio" }).click();
    await expect(page.getByRole("alert")).toContainText("3 cada 24 horas");
  });
});
