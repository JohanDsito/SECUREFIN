import { expect, test } from "@playwright/test";

const welcomeAccount = {
  id: "c9617f9b-1479-4cca-9e6d-2a99c283afe6",
  masked_number: "SF-DEMO-****-A19F",
  type: "savings",
  currency: "COP",
  available_balance_minor: 500_000_000,
  status: "active",
  created_at: "2026-01-01T12:00:00Z",
};

const usdAccount = {
  id: "2ec740df-9f63-42a8-88d5-1e4ba233b357",
  masked_number: "SF-DEMO-****-B21C",
  type: "checking",
  currency: "USD",
  available_balance_minor: 0,
  status: "active",
  created_at: "2026-01-02T12:00:00Z",
};

test("muestra saldos ficticios y permite abrir y consultar una cuenta adicional", async ({ page }) => {
  let accounts = [welcomeAccount];
  let createPayload;
  const dashboard = () => ({
    balances: {
      COP: accounts.filter((account) => account.currency === "COP")
        .reduce((sum, account) => sum + account.available_balance_minor, 0),
      USD: accounts.filter((account) => account.currency === "USD")
        .reduce((sum, account) => sum + account.available_balance_minor, 0),
    },
    accounts,
    recent_transactions: [],
    unread_notifications: 0,
  });

  await page.addInitScript(() => {
    document.cookie = "__Host-sf_csrftoken=e2e-token; Path=/; Secure; SameSite=Strict";
  });
  await page.route("**/api/v1/finance/dashboard", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(dashboard()) }),
  );
  await page.route("**/api/v1/finance/accounts", async (route) => {
    if (route.request().method() !== "POST") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(accounts) });
    }
    createPayload = route.request().postDataJSON();
    accounts = [...accounts, usdAccount];
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify(usdAccount),
    });
  });
  await page.route(`**/api/v1/finance/accounts/${usdAccount.id}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(usdAccount) }),
  );

  await page.goto("/finance");
  await expect(page.getByRole("heading", { name: "Tu panel financiero" })).toBeVisible();
  await expect(page.getByText("Estos saldos son ficticios y no representan dinero real ni pueden retirarse.")).toBeVisible();
  await expect(page.getByText(/5\.000\.000/).first()).toBeVisible();

  await page.getByRole("link", { name: /Abrir cuenta/ }).first().click();
  await page.getByLabel("Moneda").selectOption("USD");
  await page.getByLabel("Tipo de cuenta").selectOption("checking");
  await page.getByRole("button", { name: "Abrir cuenta de demostración" }).click();

  await expect(page).toHaveURL(/\/finance$/);
  await expect.poll(() => createPayload).toEqual({ type: "checking", currency: "USD" });
  await expect(page.getByText("SF-DEMO-****-B21C")).toBeVisible();
  await page.getByRole("link", { name: "Ver detalle" }).nth(1).click();
  await expect(page.getByRole("heading", { name: "Cuenta corriente USD" })).toBeVisible();
  await expect(page.getByText("Saldo de demostración disponible")).toBeVisible();
});
