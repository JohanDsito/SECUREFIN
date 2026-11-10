import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client.js";
import ConfirmButton from "../../components/ConfirmButton.jsx";
import { adminErrorMessage, fieldMessages, needsLogin } from "./errors.js";

// Gestión de usuarios (T093; FR-019, FR-020, FR-021; contrato §4). La interfaz solo es una ayuda:
// todas las reglas (rol Administrador con MFA, autooperaciones, último Administrador, estados) se
// aplican en el servidor, que es quien responde 401/403/409. Sobre la propia cuenta no se ofrecen
// acciones. Las acciones que cambian el acceso de otra persona piden confirmación; mientras una
// petición está en curso, el resto de acciones quedan deshabilitadas (sin envíos dobles).
const ROLES = [
  ["client", "Cliente"],
  ["admin", "Administrador"],
  ["auditor", "Auditor"],
];
const STATUSES = [
  ["active", "Activa"],
  ["pending_activation", "Pendiente de activación"],
  ["deactivated", "Desactivada"],
];
const label = (pairs, value) => pairs.find(([v]) => v === value)?.[1] ?? value;

function ErrorNotice({ error }) {
  return (
    <div role="alert">
      <p>
        {adminErrorMessage(error)} {needsLogin(error) && <Link to="/login">Iniciar sesión</Link>}
      </p>
      {fieldMessages(error).length > 0 && (
        <ul>
          {fieldMessages(error).map((m) => (
            <li key={m.key}>{m.text}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function Users() {
  const [me, setMe] = useState(null);
  const [filters, setFilters] = useState({ role: "", status: "", page: 1 });
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const load = useCallback(() => {
    const query = new URLSearchParams();
    if (filters.role) query.set("role", filters.role);
    if (filters.status) query.set("status", filters.status);
    query.set("page", String(filters.page));
    setState((s) => ({ ...s, loading: true }));
    return api(`/admin/users?${query}`)
      .then((data) => setState({ loading: false, data, error: null }))
      .catch((error) => setState({ loading: false, data: null, error }));
  }, [filters]);

  useEffect(() => {
    api("/auth/session")
      .then((s) => setMe(s.user))
      .catch(() => setMe(null));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  async function run(action, success) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage({ ok: true, text: success });
      return true;
    } catch (error) {
      setMessage({ ok: false, error });
      return false;
    } finally {
      setBusy(false);
      load();
    }
  }

  async function onCreate(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const body = { email: form.get("email"), name: form.get("name"), role: form.get("role") };
    const ok = await run(
      () => api("/admin/users", { method: "POST", body }),
      "Cuenta creada en estado pendiente: el enlace de activación llegará al buzón de laboratorio.",
    );
    if (ok) formElement.reset();
  }

  if (state.error) {
    return (
      <section>
        <h1>Usuarios</h1>
        <ErrorNotice error={state.error} />
        <p>
          <Link to="/">Volver</Link>
        </p>
      </section>
    );
  }
  if (!state.data) return <p role="status">Cargando…</p>;
  const { results, next, previous } = state.data;

  return (
    <section aria-busy={state.loading || busy}>
      <h1>Usuarios</h1>
      {busy && <p role="status">Procesando…</p>}
      {message?.ok && <p role="status">{message.text}</p>}
      {message && !message.ok && <ErrorNotice error={message.error} />}

      <form id="admin-create-user" name="create-user" method="post" onSubmit={onCreate}>
        <h2>Crear Administrador o Auditor</h2>
        <label htmlFor="new-user-email">Correo (ficticio)</label>
        <input id="new-user-email" name="email" type="email" autoComplete="off" required />
        <label htmlFor="new-user-name">Nombre</label>
        <input id="new-user-name" name="name" type="text" autoComplete="off" maxLength={100} required />
        <label htmlFor="new-user-role">Rol</label>
        <select id="new-user-role" name="role" defaultValue="auditor">
          <option value="auditor">Auditor</option>
          <option value="admin">Administrador</option>
        </select>
        <p className="hint">La persona recibirá un enlace de un solo uso (24 h) y fijará su propia contraseña.</p>
        <button type="submit" disabled={busy}>
          Crear y enviar activación
        </button>
      </form>

      <h2>Listado</h2>
      <p>
        <label htmlFor="filter-role">Rol </label>
        <select
          id="filter-role"
          value={filters.role}
          onChange={(e) => setFilters({ ...filters, role: e.target.value, page: 1 })}
        >
          <option value="">Todos</option>
          {ROLES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>{" "}
        <label htmlFor="filter-status">Estado </label>
        <select
          id="filter-status"
          value={filters.status}
          onChange={(e) => setFilters({ ...filters, status: e.target.value, page: 1 })}
        >
          <option value="">Todos</option>
          {STATUSES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </p>
      {state.loading && <p role="status">Cargando…</p>}
      {results.length === 0 ? (
        <p>No hay usuarios con estos filtros.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Correo</th>
              <th scope="col">Nombre</th>
              <th scope="col">Rol</th>
              <th scope="col">Estado</th>
              <th scope="col">MFA</th>
              <th scope="col">Último acceso</th>
              <th scope="col">Acciones</th>
            </tr>
          </thead>
          <tbody>
            {results.map((u) => (
              <UserRow key={u.id} user={u} isSelf={me?.id === u.id} run={run} busy={busy} />
            ))}
          </tbody>
        </table>
      )}
      <p>
        <button type="button" disabled={!previous || state.loading} onClick={() => setFilters({ ...filters, page: previous })}>
          Anterior
        </button>{" "}
        <button type="button" disabled={!next || state.loading} onClick={() => setFilters({ ...filters, page: next })}>
          Siguiente
        </button>
      </p>
      <p>
        <Link to="/admin/mfa-resets">Reinicios de MFA</Link> · <Link to="/">Volver</Link>
      </p>
    </section>
  );
}

function UserRow({ user, isSelf, run, busy }) {
  const [role, setRole] = useState(user.role);
  const base = `/admin/users/${encodeURIComponent(user.id)}`;

  return (
    <tr>
      <td>{user.email}</td>
      <td>{user.name}</td>
      <td>{label(ROLES, user.role)}</td>
      <td>{label(STATUSES, user.status)}</td>
      <td>{user.mfa_enabled ? "Sí" : "No"}</td>
      <td>{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "—"}</td>
      <td>
        {isSelf ? (
          <em>Tu cuenta</em>
        ) : (
          <>
            <select
              aria-label={`Nuevo rol para ${user.email}`}
              value={role}
              disabled={busy}
              onChange={(e) => setRole(e.target.value)}
            >
              {ROLES.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>{" "}
            <ConfirmButton
              label="Cambiar rol"
              question={`¿Cambiar el rol de ${user.email} a ${label(ROLES, role)}? Se cerrarán sus sesiones.`}
              disabled={busy || role === user.role}
              onConfirm={() =>
                run(() => api(`${base}/role`, { method: "PATCH", body: { role } }), "Rol cambiado; se cerraron sus sesiones.")
              }
            />{" "}
            {user.status === "active" && (
              <ConfirmButton
                label="Desactivar"
                question={`¿Desactivar ${user.email}? Se cerrarán sus sesiones y no podrá iniciar sesión.`}
                disabled={busy}
                onConfirm={() =>
                  run(() => api(`${base}/deactivate`, { method: "POST", body: {} }), "Cuenta desactivada.")
                }
              />
            )}
            {user.status === "deactivated" && (
              <ConfirmButton
                label="Reactivar"
                question={`¿Reactivar ${user.email}?`}
                disabled={busy}
                onConfirm={() =>
                  run(() => api(`${base}/reactivate`, { method: "POST", body: {} }), "Cuenta reactivada.")
                }
              />
            )}
            {user.status === "pending_activation" && (
              <ConfirmButton
                label="Reenviar activación"
                question={`¿Enviar un nuevo enlace a ${user.email}? El anterior dejará de valer.`}
                disabled={busy}
                onConfirm={() =>
                  run(
                    () => api(`${base}/activation/resend`, { method: "POST", body: {} }),
                    "Se enviará un nuevo enlace de activación; el anterior deja de valer.",
                  )
                }
              />
            )}
          </>
        )}
      </td>
    </tr>
  );
}
