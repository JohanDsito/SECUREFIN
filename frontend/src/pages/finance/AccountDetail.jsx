import { useEffect, useState } from "react";
import ClientOnly from "../../components/finance/ClientOnly.jsx";
import { StatusPill } from "../../lib/labels.jsx";
import { Link, useParams } from "react-router";
import { api } from "../../api/client.js";

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

export default function AccountDetail() {
  const { accountId } = useParams();
  const [state, setState] = useState({ loading: true, account: null, error: false });
  const [copied, setCopied] = useState(false);

  async function copyId(id) {
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  useEffect(() => {
    api(`/finance/accounts/${encodeURIComponent(accountId)}`)
      .then((account) => setState({ loading: false, account, error: false }))
      .catch((e) => setState({ loading: false, account: null, error: true, forbidden: e?.status === 403 }));
  }, [accountId]);

  if (state.loading) return <p role="status">Cargando cuenta…</p>;
  if (state.forbidden) return <ClientOnly />;
  if (state.error) {
    return (
      <section className="finance-page">
        <h1>Cuenta no disponible</h1>
        <p role="alert">No se encontró una cuenta disponible para tu usuario.</p>
        <Link to="/finance">Volver al panel</Link>
      </section>
    );
  }

  const { account } = state;
  return (
    <section className="finance-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Detalle de cuenta · Simulación</p>
      <h1>{account.type === "checking" ? "Cuenta corriente" : "Cuenta de ahorros"} {account.currency}</h1>
      <p className="account-meta">{account.masked_number} <StatusPill status={account.status} /></p>
      <div className="receive-box">
        <div>
          <strong>Para recibir transferencias</strong>
          <span>Comparte este ID público con quien te va a enviar dinero ficticio:</span>
          <code>{account.id}</code>
        </div>
        <div className="receive-box__actions">
          <button type="button" onClick={() => copyId(account.id)}>{copied ? "✔ Copiado" : "Copiar ID"}</button>
          <Link className="finance-button" to={`/finance/transfer?from=${account.id}`}>Transferir desde esta cuenta</Link>
        </div>
      </div>
      <div className="finance-summary-card finance-detail-balance">
        <span>Saldo de demostración disponible</span>
        <strong>{formatAmount(account.available_balance_minor, account.currency)}</strong>
        <small>Este saldo es ficticio y no se puede retirar.</small>
      </div>
      <dl className="finance-detail-list">
        <dt>Moneda</dt><dd>{account.currency}</dd>
        <dt>Tipo de cuenta</dt><dd>{account.type === "checking" ? "Corriente" : "Ahorros"}</dd>
        <dt>Fecha de apertura</dt><dd>{new Date(account.created_at).toLocaleString("es-CO")}</dd>
        <dt>Identificador visible</dt><dd>{account.masked_number}</dd>
        <dt>ID público de cuenta</dt><dd><code>{account.id}</code></dd>
      </dl>
    </section>
  );
}
