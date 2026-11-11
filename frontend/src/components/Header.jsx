import { useEffect, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router";
import { api } from "../api/client.js";

const ROLE_LABEL = { client: "Cliente", admin: "Administrador", auditor: "Auditor" };

// Encabezado consciente de la sesión: consulta /auth/session en cada cambio de ruta. La cookie es
// HttpOnly, así que el SPA no "sabe" si hay sesión: se lo pregunta al servidor (Zero Trust).
export default function Header() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [user, setUser] = useState(null);

  useEffect(() => {
    let alive = true;
    api("/auth/session")
      .then((data) => alive && setUser(data.user))
      .catch(() => alive && setUser(null));
    return () => {
      alive = false;
    };
  }, [pathname]);

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => null);
    setUser(null);
    navigate("/login");
  }

  return (
    <header>
      <Link className="brand" to="/" aria-label="SecureFin, inicio">
        <span className="brand-mark" aria-hidden="true">S</span>
        <span className="brand-copy">
          <strong>SecureFin <span>Gateway</span></strong>
          <small>Fintech simulada · Laboratorio de ciberseguridad</small>
        </span>
      </Link>
      <nav aria-label="Navegación principal">
        <NavLink className="nav-link" to="/seguridad">Centro de seguridad</NavLink>
        {user ? (
          <>
            {user.role === "client" && <NavLink className="nav-link" to="/finance">Mi dinero</NavLink>}
            {user.role === "admin" && <NavLink className="nav-link" to="/admin/users">Usuarios</NavLink>}
            {(user.role === "admin" || user.role === "auditor") && (
              <NavLink className="nav-link" to="/admin/finance/approvals">Aprobaciones</NavLink>
            )}
            <Link className="user-chip" to="/profile" title="Mi perfil">
              <span className="user-chip__avatar" aria-hidden="true">{(user.name || "?").slice(0, 1).toUpperCase()}</span>
              <span className="user-chip__copy">
                <strong>{user.name}</strong>
                <small>{ROLE_LABEL[user.role] ?? user.role}</small>
              </span>
            </Link>
            <button type="button" className="nav-logout" onClick={logout}>Salir</button>
          </>
        ) : (
          <>
            <span className="environment-badge"><span aria-hidden="true" />Laboratorio</span>
            <NavLink className="nav-link" to="/login">Iniciar sesión</NavLink>
            <Link className="nav-cta" to="/register">Crear cuenta</Link>
          </>
        )}
      </nav>
    </header>
  );
}
