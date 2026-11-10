import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ApiError, api } from "../../api/client.js";

function toMinorUnits(value) {
  const normalized = value.trim().replace(",", ".");
  if (!/^\d+(\.\d{1,2})?$/.test(normalized)) return null;
  const [whole, fraction = ""] = normalized.split(".");
  const minor = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  return minor <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(minor) : null;
}

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

function idempotencyKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export default function Transfer() {
  const [accounts, setAccounts] = useState([]);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/finance/dashboard")
      .then((data) => setAccounts(data.accounts))
      .catch(() => setError("Inicia sesión para preparar una transferencia simulada."));
  }, []);

  async function onPreview(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const account = accounts.find((item) => item.id === form.get("source_account_id"));
    const amountMinor = toMinorUnits(String(form.get("amount")));
    if (!account || amountMinor === null || amountMinor <= 0) {
      setError("Selecciona una cuenta e ingresa un importe positivo con máximo dos decimales.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const request = {
        source_account_id: account.id,
        destination_account_id: String(form.get("destination_account_id")).trim(),
        amount_minor: amountMinor,
        currency: account.currency,
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

  return (
    <section className="finance-page finance-transfer-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Operación simulada</p>
      <h1>Transferir fondos</h1>
      <p>Previsualiza la operación y confirma solo después de revisar los datos.</p>
      <div className="finance-notice" role="note">
        <strong>Sin dinero real</strong>
        <span>Esta transferencia solo mueve saldos ficticios entre cuentas SecureFin.</span>
      </div>

      <form className="finance-account-form" onSubmit={onPreview}>
        <label htmlFor="transfer-source">Cuenta de origen</label>
        <select id="transfer-source" name="source_account_id" required defaultValue="">
          <option value="" disabled>Selecciona una cuenta</option>
          {accounts.filter((account) => account.status === "active").map((account) => (
            <option key={account.id} value={account.id}>
              {account.masked_number} · {account.currency} · {formatAmount(account.available_balance_minor, account.currency)}
            </option>
          ))}
        </select>
        <label htmlFor="transfer-destination">ID de cuenta destino</label>
        <input
          id="transfer-destination"
          name="destination_account_id"
          type="text"
          inputMode="text"
          autoComplete="off"
          placeholder="UUID de otra cuenta SecureFin"
          required
        />
        <p className="finance-form-hint">Usa el identificador público de una cuenta de demostración activa.</p>
        <label htmlFor="transfer-amount">Importe</label>
        <input id="transfer-amount" name="amount" type="text" inputMode="decimal" placeholder="0,00" required />
        <label htmlFor="transfer-description">Descripción (opcional)</label>
        <input id="transfer-description" name="description" type="text" maxLength={140} />
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={busy || accounts.length === 0}>
          {busy ? "Validando…" : "Revisar transferencia"}
        </button>
      </form>

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
        <div className="finance-transfer-preview" role="status">
          <h2>{result.status === "completed" ? "Transferencia completada" : "Solicitud recibida"}</h2>
          <p>Referencia: <code>{result.id}</code></p>
          <p>{result.status === "pending_approval" ? "El saldo no cambiará hasta completar las aprobaciones requeridas." : "Los saldos se actualizaron de forma simulada."}</p>
          <Link to={`/finance/transfers/${result.id}`}>Ver estado de la transferencia</Link>
        </div>
      )}
    </section>
  );
}
