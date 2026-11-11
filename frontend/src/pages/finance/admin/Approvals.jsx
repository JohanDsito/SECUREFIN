import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../../../api/client.js";

function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(amountMinor / 100);
}

export default function Approvals() {
  const [approvals, setApprovals] = useState([]);
  const [role, setRole] = useState("");
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    try {
      const [session, queue] = await Promise.all([
        api("/auth/session"),
        api("/admin/finance/approvals"),
      ]);
      setRole(session.user.role);
      setApprovals(queue);
      setError("");
    } catch {
      setError("No se pudo cargar la cola de aprobaciones. Inicia sesión con un Administrador o Auditor.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function decide(id, decision, event) {
    event.preventDefault();
    const form = event.currentTarget.closest("form");
    const reason = new FormData(form).get("reason")?.toString().trim() ?? "";
    if (decision === "reject" && !reason) {
      setError("Escribe un motivo breve para rechazar la operación.");
      return;
    }
    setBusyId(id);
    setError("");
    setMessage("");
    try {
      await api(`/admin/finance/transfers/${id}/${decision}`, {
        method: "POST",
        body: { reason },
      });
      setMessage(decision === "approve" ? "Decisión registrada." : "Transferencia rechazada.");
      await load();
    } catch (requestError) {
      setError(
        requestError.status === 409
          ? requestError.message || "La solicitud ya fue resuelta o tus detalles requieren revisión."
          : "No se pudo registrar la decisión.",
      );
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="finance-page">
      <Link to="/" className="finance-back-link">← Volver a inicio</Link>
      <p className="finance-eyebrow">Control administrativo · MFA requerido</p>
      <h1>Cola de aprobaciones</h1>
      <p>Las solicitudes pendientes no alteran saldos hasta completar el número de aprobaciones.</p>
      <div className="finance-notice" role="note">
        <strong>Operaciones ficticias</strong>
        <span>Esta cola pertenece al laboratorio y no autoriza pagos reales.</span>
      </div>
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      {loading ? (
        <p role="status">Cargando solicitudes…</p>
      ) : approvals.length ? (
        <ul className="finance-approval-list">
          {approvals.map((approval) => (
            <li key={approval.id}>
              <div className="finance-approval-list__heading">
                <div>
                  <strong>{formatAmount(approval.amount_minor, approval.currency)}</strong>
                  <small>{approval.currency} · {approval.creator_email}</small>
                </div>
                <span className="finance-count">
                  {approval.approvals_received}/{approval.approval_count_required} aprobaciones
                </span>
              </div>
              <p>{approval.source_account} → {approval.destination_account}</p>
              <p>{approval.description || "Sin descripción"} · {new Date(approval.created_at).toLocaleString("es-CO")}</p>
              {role === "admin" && (
                <form className="finance-approval-actions" onSubmit={(event) => event.preventDefault()}>
                  <label htmlFor={`approval-reason-${approval.id}`}>Motivo de decisión</label>
                  <input
                    id={`approval-reason-${approval.id}`}
                    name="reason"
                    maxLength={240}
                    placeholder="No incluyas datos de tarjeta o credenciales"
                  />
                  <button
                    type="button"
                    disabled={busyId === approval.id}
                    onClick={(event) => decide(approval.id, "approve", event)}
                  >
                    Aprobar
                  </button>
                  <button
                    type="button"
                    disabled={busyId === approval.id}
                    onClick={(event) => decide(approval.id, "reject", event)}
                  >
                    Rechazar
                  </button>
                </form>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <div className="finance-empty">
          <strong>No hay solicitudes pendientes</strong>
          <p>Las nuevas solicitudes de aprobación aparecerán aquí.</p>
        </div>
      )}
    </section>
  );
}
