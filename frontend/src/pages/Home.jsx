import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { api } from "../api/client.js";

// Área personal (T056). Si no hay sesión `full`, invita a iniciar sesión.
export default function Home() {
  const navigate = useNavigate();
  const remaining = useLocation().state?.recoveryCodesRemaining;
  const [state, setState] = useState({ loading: true, data: null });

  useEffect(() => {
    api("/auth/session")
      .then((data) => setState({ loading: false, data }))
      .catch(() => setState({ loading: false, data: null }));
  }, []);

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => null);
    setState({ loading: false, data: null });
    navigate("/login");
  }

  if (state.loading) return <p>Cargando…</p>;
  if (!state.data) {
    return (
      <p>
        No has iniciado sesión. <Link to="/login">Inicia sesión</Link>
      </p>
    );
  }
  const { user, session } = state.data;
  return (
    <section>
      <h1>Hola, {user.name}</h1>
      {remaining !== undefined && (
        <p role="status">
          Has usado un código de recuperación. Te quedan {remaining}. Si perdiste tu dispositivo, reconfigura el MFA
          desde <Link to="/profile">tu perfil</Link>.
        </p>
      )}
      <p>Rol: {user.role}</p>
      <p>La sesión caduca por inactividad a las {new Date(session.idle_expires_at).toLocaleTimeString()}.</p>
      <p>
        <Link to="/finance">Panel financiero</Link> · <Link to="/profile">Mi perfil</Link> · <Link to="/sessions">Mis sesiones</Link>
      </p>
      {user.role === "admin" && (
        <p>
          Administración: <Link to="/admin/users">Usuarios</Link> · <Link to="/admin/mfa-resets">Reinicios de MFA</Link> · <Link to="/admin/finance/approvals">Aprobaciones financieras</Link>
        </p>
      )}
      {user.role === "auditor" && (
        <p><Link to="/admin/finance/approvals">Consultar aprobaciones financieras</Link></p>
      )}
      <button type="button" onClick={logout}>Cerrar sesión</button>
    </section>
  );
}
