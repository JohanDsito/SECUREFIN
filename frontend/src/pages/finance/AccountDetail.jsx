import { useEffect, useState } from "react";
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

  useEffect(() => {
    api(`/finance/accounts/${encodeURIComponent(accountId)}`)
      .then((account) => setState({ loading: false, account, error: false }))
      .catch(() => setState({ loading: false, account: null, error: true }));
  }, [accountId]);

  if (state.loading) return <p role="status">Cargando cuenta…</p>;
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
      <p>{account.masked_number} · {account.status === "active" ? "Activa" : account.status}</p>
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
