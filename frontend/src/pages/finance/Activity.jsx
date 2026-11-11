import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client.js";
import ClientOnly from "../../components/finance/ClientOnly.jsx";
import { KIND_LABEL, StatusPill, formatAmount, formatDate } from "../../lib/labels.jsx";

const FILTERS = [
  ["", "Todas"],
  ["completed", "Completadas"],
  ["pending_approval", "Pendientes"],
  ["rejected", "Rechazadas"],
];

export default function Activity() {
  const [status, setStatus] = useState("");
  const [state, setState] = useState({ loading: true, rows: [], error: "", forbidden: false });

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    api(`/finance/transactions${status ? `?status=${status}` : ""}`)
      .then((data) => setState({ loading: false, rows: data.results, error: "" }))
      .catch((e) => setState({ loading: false, rows: [], error: "No se pudo cargar tu actividad.", forbidden: e?.status === 403 }));
  }, [status]);

  if (state.forbidden) return <ClientOnly />;
  return (
    <section className="finance-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Historial propio</p>
      <h1>Actividad financiera</h1>
      <p>Movimientos ficticios relacionados únicamente con tus cuentas (el servidor filtra por propietario).</p>
      <div className="filter-tabs" role="group" aria-label="Filtrar por estado">
        {FILTERS.map(([value, label]) => (
          <button type="button" key={value} className={status === value ? "is-selected" : ""} onClick={() => setStatus(value)}>
            {label}
          </button>
        ))}
      </div>
      {state.error && <p role="alert">{state.error}</p>}
      {state.loading ? (
        <p role="status">Cargando actividad…</p>
      ) : state.rows.length ? (
        <div className="finance-table-wrap">
          <table>
            <thead>
              <tr><th>Fecha</th><th>Tipo</th><th>Origen → destino</th><th>Estado</th><th>Importe</th><th></th></tr>
            </thead>
            <tbody>
              {state.rows.map((row) => (
                <tr key={row.id}>
                  <td>{formatDate(row.created_at)}</td>
                  <td>{KIND_LABEL[row.kind] ?? row.kind}</td>
                  <td className="mono">{row.source_account ?? "SecureFin"} → {row.destination_account ?? "—"}</td>
                  <td><StatusPill status={row.status} /></td>
                  <td className="amount">{formatAmount(row.amount_minor, row.currency)}</td>
                  <td>{row.kind === "transfer" && <Link to={`/finance/transfers/${row.id}`}>Ver</Link>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="finance-empty">
          <strong>Aún no hay movimientos</strong>
          <p>Las operaciones de demostración aparecerán aquí.</p>
          <Link className="finance-button" to="/finance/transfer">Hacer una transferencia</Link>
        </div>
      )}
    </section>
  );
}
