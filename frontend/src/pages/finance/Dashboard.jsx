import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ApiError, api } from "../../api/client.js";
import ClientOnly from "../../components/finance/ClientOnly.jsx";
import AccountCard from "../../components/finance/AccountCard.jsx";
import { KIND_LABEL, StatusPill } from "../../lib/labels.jsx";

const currencyLabels = { COP: "Pesos colombianos", USD: "Dólares estadounidenses" };

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

export default function Dashboard() {
  const [state, setState] = useState({ loading: true, data: null, error: null, forbidden: false });

  useEffect(() => {
    api("/finance/dashboard")
      .then((data) => setState({ loading: false, data, error: null }))
      .catch((error) =>
        setState({
          forbidden: error instanceof ApiError && error.status === 403,
          loading: false,
          data: null,
          error:
            error instanceof ApiError && error.status === 401
              ? "Inicia sesión para consultar tus cuentas."
              : "No se pudo cargar el panel financiero. Inténtalo nuevamente.",
        }),
      );
  }, []);

  if (state.loading) return <p role="status">Cargando tu panel financiero…</p>;
  if (state.forbidden) return <ClientOnly />;
  if (!state.data) {
    return (
      <section className="finance-page">
        <h1>Tu panel financiero</h1>
        <p role="alert">{state.error}</p>
        <Link className="finance-button" to="/login">Iniciar sesión</Link>
      </section>
    );
  }

  const { balances, accounts, recent_transactions: transactions, unread_notifications: unread } = state.data;
  return (
    <section className="finance-page">
      <div className="finance-page__heading">
        <div>
          <p className="finance-eyebrow">SecureFin · Simulación financiera</p>
          <h1>Tu panel financiero</h1>
          <p>Un resumen claro de tus cuentas y actividad ficticia.</p>
        </div>
        <Link className="finance-button" to="/finance/accounts/new">＋ Abrir cuenta</Link>
      </div>
      <div className="finance-quick-actions">
        <Link className="finance-quick-action" to="/finance/transfer">↗ <span>Transferir fondos</span></Link>
        <Link className="finance-quick-action" to="/finance/activity">▤ <span>Ver movimientos</span></Link>
      </div>

      <div className="finance-notice" role="note">
        <strong>Entorno de demostración</strong>
        <span>Estos saldos son ficticios y no representan dinero real ni pueden retirarse.</span>
      </div>

      <div className="finance-summary-grid" aria-label="Saldos por moneda">
        {Object.entries(currencyLabels).map(([currency, label]) => (
          <article className="finance-summary-card" key={currency}>
            <span>{label}</span>
            <strong>{formatAmount(balances[currency] ?? 0, currency)}</strong>
            <small>Saldo de demostración · {currency}</small>
          </article>
        ))}
        <article className="finance-summary-card finance-summary-card--quiet">
          <span>Avisos por revisar</span>
          <strong>{unread}</strong>
          <small>Notificaciones de tu actividad</small>
        </article>
      </div>

      <div className="finance-section-heading">
        <div>
          <h2>Tus cuentas</h2>
          <p>{accounts.length ? `${accounts.length} cuenta${accounts.length === 1 ? "" : "s"} de demostración` : "Aún no tienes cuentas."}</p>
        </div>
        <Link to="/finance/accounts/new">Abrir otra cuenta</Link>
      </div>
      {accounts.length ? (
        <div className="finance-account-grid">
          {accounts.map((account) => <AccountCard account={account} key={account.id} />)}
        </div>
      ) : (
        <div className="finance-empty">
          <strong>Empieza con una cuenta de demostración</strong>
          <p>Las cuentas adicionales empiezan con saldo cero.</p>
          <Link className="finance-button" to="/finance/accounts/new">Abrir cuenta</Link>
        </div>
      )}

      <div className="finance-section-heading">
        <div>
          <h2>Actividad reciente</h2>
          <p>Las operaciones se registran de forma segura en este entorno.</p>
        </div>
        <span className="finance-count">{transactions.length} recientes</span>
      </div>
      {transactions.length ? (
        <ul className="finance-activity-list">
          {transactions.map((item) => (
            <li key={item.id}>
              <span className="finance-activity-mark" aria-hidden="true">↗</span>
              <div>
                <strong>
                  {KIND_LABEL[item.kind] ?? item.kind}
                </strong>
                <small>{new Date(item.created_at).toLocaleString("es-CO")} <StatusPill status={item.status} /></small>
              </div>
              <span className="finance-activity-amount">
                {formatAmount(item.amount_minor, item.currency)}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="finance-empty-inline">Tu actividad aparecerá aquí.</p>
      )}
    </section>
  );
}
