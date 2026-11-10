import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client.js";

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

export default function Activity() {
  const [state, setState] = useState({ loading: true, rows: [], error: "" });

  useEffect(() => {
    api("/finance/transactions")
      .then((data) => setState({ loading: false, rows: data.results, error: "" }))
      .catch(() => setState({ loading: false, rows: [], error: "No se pudo cargar tu actividad." }));
  }, []);

  if (state.loading) return <p role="status">Cargando actividad…</p>;
  return (
    <section className="finance-page">
      <Link to="/finance" className="finance-back-link">← Volver al panel</Link>
      <p className="finance-eyebrow">Historial propio</p>
      <h1>Actividad financiera</h1>
      <p>Movimientos ficticios relacionados únicamente con tus cuentas.</p>
      {state.error && <p role="alert">{state.error}</p>}
      {state.rows.length ? (
        <div className="finance-table-wrap">
          <table>
            <thead>
              <tr><th>Fecha</th><th>Tipo</th><th>Referencia</th><th>Estado</th><th>Importe</th></tr>
            </thead>
            <tbody>
              {state.rows.map((row) => (
                <tr key={row.id}>
                  <td>{new Date(row.created_at).toLocaleString("es-CO")}</td>
                  <td>{row.kind === "opening_credit" ? "Saldo de bienvenida" : "Transferencia simulada"}</td>
                  <td>{row.source_account ?? "—"} → {row.destination_account ?? "—"}</td>
                  <td>{row.status}</td>
                  <td>{formatAmount(row.amount_minor, row.currency)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="finance-empty">
          <strong>Aún no hay movimientos</strong>
          <p>Las operaciones de demostración aparecerán aquí.</p>
        </div>
      )}
    </section>
  );
}
