import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { api } from "../../api/client.js";
import ClientOnly from "../../components/finance/ClientOnly.jsx";
import { KIND_LABEL, StatusPill, formatAmount, formatDate } from "../../lib/labels.jsx";

const STEPS = [
  ["Solicitada", () => true],
  ["Revisión de límites y riesgo", () => true],
  ["Aprobación", (s) => s !== "pending_approval"],
  ["Aplicada al saldo", (s) => s === "completed"],
];

export default function TransferResult() {
  const { transactionId } = useParams();
  const [state, setState] = useState({ loading: true, transaction: null });

  useEffect(() => {
    api(`/finance/transfers/${encodeURIComponent(transactionId)}`)
      .then((transaction) => setState({ loading: false, transaction }))
      .catch((e) => setState({ loading: false, transaction: null, forbidden: e?.status === 403 }));
  }, [transactionId]);

  if (state.loading) return <p role="status">Cargando estado…</p>;
  if (state.forbidden) return <ClientOnly />;
  if (!state.transaction) {
    return (
      <section className="finance-page">
        <h1>Transferencia no disponible</h1>
        <p role="alert">No se encontró una transferencia propia con esa referencia.</p>
        <Link to="/finance">Volver al panel</Link>
      </section>
    );
  }

  const t = state.transaction;
  return (
    <section className="finance-page">
      <Link to="/finance/activity" className="finance-back-link">← Ver todos los movimientos</Link>
      <p className="finance-eyebrow">Comprobante de operación simulada</p>
      <h1>Estado de la transferencia</h1>
      <div className="receipt-head">
        <strong className="receipt-amount">{formatAmount(t.amount_minor, t.currency)}</strong>
        <StatusPill status={t.status} />
      </div>
      <ol className="timeline">
        {STEPS.map(([label, done]) => {
          const isDone = t.status !== "rejected" ? done(t.status) : label !== "Aplicada al saldo";
          const failed = t.status === "rejected" && label === "Aprobación";
          return (
            <li key={label} className={failed ? "is-bad" : isDone ? "is-done" : ""}>
              {failed ? "Rechazada" : label}
            </li>
          );
        })}
      </ol>
      <dl className="finance-detail-list">
        <dt>Tipo</dt><dd>{KIND_LABEL[t.kind] ?? t.kind}</dd>
        <dt>Descripción</dt><dd>{t.description || "Sin descripción"}</dd>
        <dt>Referencia</dt><dd><code>{t.id}</code></dd>
        <dt>Creada</dt><dd>{formatDate(t.created_at)}</dd>
      </dl>
    </section>
  );
}
