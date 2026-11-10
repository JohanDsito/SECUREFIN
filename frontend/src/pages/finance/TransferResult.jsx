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

export default function TransferResult() {
  const { transactionId } = useParams();
  const [state, setState] = useState({ loading: true, transaction: null });

  useEffect(() => {
    api(`/finance/transfers/${encodeURIComponent(transactionId)}`)
      .then((transaction) => setState({ loading: false, transaction }))
      .catch(() => setState({ loading: false, transaction: null }));
  }, [transactionId]);

  if (state.loading) return <p role="status">Cargando estado…</p>;
  if (!state.transaction) {
    return (
      <section className="finance-page">
        <h1>Transferencia no disponible</h1>
        <p role="alert">No se encontró una transferencia propia con esa referencia.</p>
        <Link to="/finance">Volver al panel</Link>
      </section>
    );
  }

  const transaction = state.transaction;
  return (
    <section className="finance-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Referencia de operación</p>
      <h1>Estado de la transferencia</h1>
      <dl className="finance-detail-list">
        <dt>Estado</dt><dd>{transaction.status}</dd>
        <dt>Importe</dt><dd>{formatAmount(transaction.amount_minor, transaction.currency)}</dd>
        <dt>Tipo</dt><dd>{transaction.kind}</dd>
        <dt>Descripción</dt><dd>{transaction.description || "Sin descripción"}</dd>
        <dt>Referencia</dt><dd>{transaction.id}</dd>
        <dt>Creada</dt><dd>{new Date(transaction.created_at).toLocaleString("es-CO")}</dd>
      </dl>
    </section>
  );
}
