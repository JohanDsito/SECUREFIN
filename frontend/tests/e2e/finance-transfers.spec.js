import { expect, test } from "@playwright/test";

const source = {
  id: "c9617f9b-1479-4cca-9e6d-2a99c283afe6",
  masked_number: "SF-DEMO-****-A19F",
  type: "savings",
  currency: "COP",
  available_balance_minor: 500_000_000,
  status: "active",
  created_at: "2026-01-01T12:00:00Z",
};

const destinationId = "2ec740df-9f63-42a8-88d5-1e4ba233b357";
let requestBody;
let requestKey;

test.beforeEach(async ({ page }) => {
  requestBody = null;
  requestKey = null;
  await page.addInitScript(() => {
    document.cookie = "__Host-sf_csrftoken=e2e-token; Path=/; Secure; SameSite=Strict";
  });
  await page.route("**/api/v1/finance/dashboard", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        balances: { COP: 500_000_000, USD: 0 },
        accounts: [source],
        recent_transactions: [],
        unread_notifications: 0,
      }),
    }),
  );
  await page.route("**/api/v1/finance/transfers/preview", async (route) => {
    requestBody = route.request().postDataJSON();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        source_account: source.masked_number,
        destination_account: "SF-DEMO-****-B21C",
        amount_minor: requestBody.amount_minor,
        currency: requestBody.currency,
        description: requestBody.description,
        fee_minor: 0,
        approval_count_required: 1,
        status: "pending_approval",
      }),
    });
  });
  await page.route("**/api/v1/finance/transfers", async (route) => {
    requestKey = route.request().headers()["idempotency-key"];
    return route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        id: "90316dd4-86c6-40df-ad72-74bcbcc55a0c",
        correlation_id: "bc899add-7156-48b4-9c4a-53094aec23fe",
        kind: "transfer",
        status: "pending_approval",
        amount_minor: requestBody.amount_minor,
        currency: requestBody.currency,
        description: requestBody.description,
        approval_count_required: 1,
        rejection_reason: "",
        created_at: "2026-01-02T12:00:00Z",
        resolved_at: null,
      }),
    });
  });
  await page.route("**/api/v1/finance/transfers/90316dd4-86c6-40df-ad72-74bcbcc55a0c", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "90316dd4-86c6-40df-ad72-74bcbcc55a0c",
        correlation_id: "bc899add-7156-48b4-9c4a-53094aec23fe",
        kind: "transfer",
        status: "pending_approval",
        amount_minor: requestBody.amount_minor,
        currency: requestBody.currency,
        description: requestBody.description,
        approval_count_required: 1,
        rejection_reason: "",
        created_at: "2026-01-02T12:00:00Z",
        resolved_at: null,
      }),
    }),
  );
  await page.goto("/finance/transfer");
});

test("requiere revisar los datos y confirmar con una clave idempotente", async ({ page }) => {
  await page.getByLabel("Cuenta de origen").selectOption(source.id);
  await page.getByLabel("ID de cuenta destino").fill(destinationId);
  await page.getByLabel("Importe").fill("12,50");
  await page.getByLabel("Descripción (opcional)").fill("Pago ficticio");
  await page.getByRole("button", { name: "Revisar transferencia" }).click();

  await expect(page.getByRole("heading", { name: "Confirma los datos" })).toBeVisible();
  expect(requestBody).toEqual({
    source_account_id: source.id,
    destination_account_id: destinationId,
    amount_minor: 1_250,
    currency: "COP",
    description: "Pago ficticio",
  });
  await page.getByRole("button", { name: "Confirmar transferencia simulada" }).click();
  await expect(page.getByRole("heading", { name: "Solicitud recibida" })).toBeVisible();
  expect(requestKey).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  await page.getByRole("link", { name: "Ver estado de la transferencia" }).click();
  await expect(page.getByRole("heading", { name: "Estado de la transferencia" })).toBeVisible();
});
