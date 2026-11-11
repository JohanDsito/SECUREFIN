import { Link } from "react-router";

const currencyNames = { COP: "Pesos colombianos", USD: "Dólares estadounidenses" };

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

export default function AccountCard({ account }) {
  return (
    <article className="finance-account-card">
      <div className="finance-account-card__top">
        <span className="finance-account-icon" aria-hidden="true">
          {account.currency === "COP" ? "$" : "＄"}
        </span>
        <span className={`finance-status finance-status--${account.status}`}>
          {account.status === "active" ? "Activa" : account.status}
        </span>
      </div>
      <p className="finance-account-card__label">
        {account.type === "checking" ? "Cuenta corriente" : "Cuenta de ahorros"} · {account.currency}
      </p>
      <strong className="finance-account-card__balance">
        {formatAmount(account.available_balance_minor, account.currency)}
      </strong>
      <div className="finance-account-card__bottom">
        <span>{account.masked_number}</span>
        <Link to={`/finance/accounts/${account.id}`}>Ver detalle</Link>
      </div>
      <small>{currencyNames[account.currency]} · Saldo de demostración</small>
    </article>
  );
}
