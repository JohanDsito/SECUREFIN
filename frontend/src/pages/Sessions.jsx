import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client.js";
import { describeUserAgent, formatDate } from "../lib/labels.jsx";

// Sesiones propias (T065; US2, FR-010). Lista las sesiones vigentes y permite revocar cualquiera de
// las otras; la revocación es inmediata en el servidor (la otra cookie deja de valer). La sesión
// actual se cierra con "Cerrar sesión", no desde esta lista.
export default function Sessions() {
  const [state, setState] = useState({ loading: true, sessions: null });
  const [message, setMessage] = useState(null);

  const load = useCallback(() => {
    api("/users/me/sessions")
      .then((sessions) => setState({ loading: false, sessions }))
      .catch(() => setState({ loading: false, sessions: null }));
  }, []);

  useEffect(load, [load]);

  async function revoke(publicId) {
    setMessage(null);
    try {
      await api(`/users/me/sessions/${encodeURIComponent(publicId)}`, { method: "DELETE" });
      setMessage("Sesión cerrada.");
    } catch {
      setMessage("No fue posible cerrar la sesión.");
    }
    load();
  }

  if (state.loading) return <p>Cargando…</p>;
  if (!state.sessions) {
    return (
      <p>
        No has iniciado sesión. <Link to="/login">Inicia sesión</Link>
      </p>
    );
  }
  return (
    <section>
      <p className="finance-eyebrow">Sesiones de servidor · revocación inmediata</p>
      <h1>Mis sesiones</h1>
      <p>Cada fila es una sesión guardada en el servidor. Si no reconoces una, ciérrala: su cookie deja de valer al instante.</p>
      {message && <p role="status">{message}</p>}
      <table>
        <thead>
          <tr>
            <th scope="col">Inicio</th>
            <th scope="col">Última actividad</th>
            <th scope="col">IP</th>
            <th scope="col">Navegador</th>
            <th scope="col">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {state.sessions.map((s) => (
            <tr key={s.public_id}>
              <td>{formatDate(s.created_at)}</td>
              <td>{formatDate(s.last_activity_at)}</td>
              <td>{s.ip_address ?? "—"}</td>
              <td title={s.user_agent ?? ""}>{describeUserAgent(s.user_agent)}</td>
              <td>
                {s.current ? (
                  <span className="pill pill--ok">Esta sesión</span>
                ) : (
                  <button type="button" onClick={() => revoke(s.public_id)}>
                    Cerrar
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        <Link to="/profile">Mi perfil</Link> · <Link to="/">Volver</Link>
      </p>
    </section>
  );
}
