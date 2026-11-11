import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiError, api } from "../../api/client.js";
import ClientOnly from "../../components/finance/ClientOnly.jsx";
import { StatusPill, formatAmount } from "../../lib/labels.jsx";

function toMinorUnits(value) {
  // "250.000" o "1.000.000" = miles (formato colombiano); "12,50" o "12.50" = decimales.
  let normalized = value.trim().replace(/[\s$]/g, "");
  if (normalized.includes(",")) normalized = normalized.replace(/\./g, "").replace(",", ".");
  else if (/^\d{1,3}(\.\d{3})+$/.test(normalized)) normalized = normalized.replace(/\./g, "");
  if (!/^\d+(\.\d{1,2})?$/.test(normalized)) return null;
  const [whole, fraction = ""] = normalized.split(".");
  const minor = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  return minor <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(minor) : null;
}

function idempotencyKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Umbrales informativos (la decisión real la toma el servidor: apps/finance/policies/limits.py).
const POLICY = {
  COP: { auto: "hasta $1.000.000", one: "hasta $5.000.000", two: "hasta $10.000.000 (máximo por operación)" },
  USD: { auto: "hasta US$250", one: "hasta US$1.250", two: "hasta US$2.500 (máximo por operación)" },
};

export default function Transfer() {
  const [params] = useSearchParams();
  const [accounts, setAccounts] = useState([]);
  const [sourceId, setSourceId] = useState(params.get("from") ?? "");
  const [destination, setDestination] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [forbidden, setForbidden] = useState(false);

  useEffect(() => {
    api("/finance/dashboard")
      .then((data) => setAccounts(data.accounts))
      .catch((e) => (e?.status === 403 ? setForbidden(true) : setError("Inicia sesión para preparar una transferencia simulada.")));
  }, []);

  const active = accounts.filter((account) => account.status === "active");
  const source = active.find((account) => account.id === sourceId);
  const ownTargets = useMemo(
    () => (source ? active.filter((a) => a.id !== source.id && a.currency === source.currency) : []),
    [active, source],
  );

  async function onPreview(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const amountMinor = toMinorUnits(String(form.get("amount")));
    if (!source || amountMinor === null || amountMinor <= 0) {
      setError("Selecciona una cuenta e ingresa un importe positivo con máximo dos decimales.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const request = {
        source_account_id: source.id,
        destination_account_id: destination.trim(),
        amount_minor: amountMinor,
        currency: source.currency,
        description: String(form.get("description")).trim(),
      };
      const data = await api("/finance/transfers/preview", { method: "POST", body: request });
      setPreview({ data, request, key: idempotencyKey() });
    } catch (requestError) {
      setPreview(null);
      setError(
        requestError instanceof ApiError && requestError.fields
          ? "Revisa los datos de la transferencia."
          : requestError.message || "No fue posible previsualizar la transferencia.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function confirmTransfer() {
    if (!preview) return;
    setBusy(true);
    setError("");
    try {
      const data = await api("/finance/transfers", {
        method: "POST",
        body: preview.request,
        headers: { "Idempotency-Key": preview.key },
      });
      setResult(data);
      setPreview(null);
      api("/finance/dashboard").then((d) => setAccounts(d.accounts)).catch(() => null);
    } catch (requestError) {
      setError(
        requestError.status === 409
          ? "La transferencia no se realizó. Verifica saldo, límites y cuentas activas."
          : "No se pudo confirmar la transferencia. La clave de solicitud se conserva para reintentar.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (forbidden) return <ClientOnly />;
  const policy = POLICY[source?.currency ?? "COP"];

  return (
    <section className="finance-page finance-transfer-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Operación simulada</p>
      <h1>Transferir fondos</h1>
      <p>Elige el origen y el destino, revisa la vista previa y confirma. Nada se mueve hasta que confirmes.</p>

      <div className="transfer-layout">
        <form className="finance-account-form transfer-form" onSubmit={onPreview}>
          <span className="transfer-step">1 · Desde</span>
          <label htmlFor="transfer-source">Cuenta de origen</label>
          <select
            id="transfer-source"
            name="source_account_id"
            required
            value={sourceId}
            onChange={(e) => {
              setSourceId(e.target.value);
              setPreview(null);
            }}
          >
            <option value="" disabled>Selecciona una cuenta</option>
            {active.map((account) => (
              <option key={account.id} value={account.id}>
                {account.masked_number} · {account.currency} · {formatAmount(account.available_balance_minor, account.currency)}
              </option>
            ))}
          </select>

          <span className="transfer-step">2 · Hacia</span>
          {ownTargets.length > 0 && (
            <div className="transfer-targets" aria-label="Tus otras cuentas en la misma moneda">
              {ownTargets.map((a) => (
                <button
                  type="button"
                  key={a.id}
                  className={destination === a.id ? "is-selected" : ""}
                  onClick={() => setDestination(a.id)}
                >
                  <strong>Mi cuenta {a.type === "checking" ? "corriente" : "de ahorros"}</strong>
                  <small>{a.masked_number}</small>
                </button>
              ))}
            </div>
          )}
          <label htmlFor="transfer-destination">ID de cuenta destino</label>
          <input
            id="transfer-destination"
            name="destination_account_id"
            type="text"
            inputMode="text"
            autoComplete="off"
            placeholder="Pega el ID público de la cuenta del destinatario"
            value={destination}
            onChange={(e) => setDestination(e.target.value)}
            required
          />
          <p className="finance-form-hint">
            {source && ownTargets.length === 0
              ? `No tienes otra cuenta ${source.currency}. `
              : ""}
            Para enviar a otra persona, pídele el <strong>ID público</strong> que aparece en el detalle de su cuenta.
          </p>

          <span className="transfer-step">3 · Cuánto</span>
          <label htmlFor="transfer-amount">Importe</label>
          <input id="transfer-amount" name="amount" type="text" inputMode="decimal" placeholder="Ej. 250000 o 12,50" required />
          <label htmlFor="transfer-description">Descripción (opcional)</label>
          <input id="transfer-description" name="description" type="text" maxLength={140} placeholder="Ej. Arriendo de demostración" />
          {error && <p role="alert">{error}</p>}
          <button type="submit" disabled={busy || accounts.length === 0}>
            {busy ? "Validando…" : "Revisar transferencia"}
          </button>
        </form>

        <aside className="transfer-aside">
          {source && (
            <div className="transfer-balance">
              <span>Saldo disponible</span>
              <strong>{formatAmount(source.available_balance_minor, source.currency)}</strong>
              <small>{source.masked_number}</small>
            </div>
          )}
          <div className="transfer-policy">
            <h2>Política de aprobación ({source?.currency ?? "COP"})</h2>
            <ul>
              <li><span className="pill pill--ok">Automática</span> {policy.auto}</li>
              <li><span className="pill pill--warn">1 Administrador</span> {policy.one}</li>
              <li><span className="pill pill--warn">2 Administradores</span> {policy.two}</li>
            </ul>
            <p>Además: límite diario, mensual y máximo 20 operaciones por día. El servidor vuelve a validar todo al confirmar (nunca confía en el navegador).</p>
          </div>
          <div className="finance-notice" role="note">
            <strong>Sin dinero real</strong>
            <span>Solo se mueven saldos ficticios entre cuentas SecureFin.</span>
          </div>
        </aside>
      </div>

      {preview && (
        <div className="finance-transfer-preview" aria-live="polite">
          <h2>Confirma los datos</h2>
          <dl>
            <dt>Desde</dt><dd>{preview.data.source_account}</dd>
            <dt>Hacia</dt><dd>{preview.data.destination_account}</dd>
            <dt>Importe</dt><dd>{formatAmount(preview.data.amount_minor, preview.data.currency)}</dd>
            <dt>Comisión</dt><dd>{formatAmount(preview.data.fee_minor, preview.data.currency)}</dd>
            <dt>Estado al confirmar</dt>
            <dd>{preview.data.status === "pending_approval" ? "Pendiente de aprobación" : "Procesamiento automático"}</dd>
          </dl>
          <button type="button" disabled={busy} onClick={confirmTransfer}>
            {busy ? "Confirmando…" : "Confirmar transferencia simulada"}
          </button>
        </div>
      )}

      {result && (
        <div className="finance-transfer-preview transfer-done" role="status">
          <h2>{result.status === "completed" ? "✔ Transferencia completada" : "Solicitud recibida"}</h2>
          <p><StatusPill status={result.status} /> Referencia: <code>{result.id}</code></p>
          <p>{result.status === "pending_approval" ? "El saldo no cambiará hasta que un Administrador (distinto de ti) la apruebe." : "Los saldos se actualizaron de forma simulada."}</p>
          <Link to={`/finance/transfers/${result.id}`}>Ver estado de la transferencia</Link>
        </div>
      )}
    </section>
  );
}
