import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client.js";

// Perfil propio (T065; US2, FR-018). Solo se puede editar el nombre: el servidor rechaza cualquier
// otro campo, de modo que el formulario no es la frontera de confianza (FR-049).
export default function Profile() {
  const [state, setState] = useState({ loading: true, profile: null, security: null });
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([api("/users/me/profile"), api("/users/me/security")])
      .then(([profile, security]) => setState({ loading: false, profile, security }))
      .catch(() => setState({ loading: false, profile: null, security: null }));
  }, []);

  async function onSubmit(event) {
    event.preventDefault();
    const name = new FormData(event.currentTarget).get("name");
    setBusy(true);
    setMessage(null);
    try {
      const profile = await api("/users/me/profile", { method: "PATCH", body: { name } });
      setState((s) => ({ ...s, profile }));
      setMessage("Nombre actualizado.");
    } catch (error) {
      setMessage(error.status === 400 ? error.message : "No fue posible guardar los cambios.");
    } finally {
      setBusy(false);
    }
  }

  if (state.loading) return <p>Cargando…</p>;
  if (!state.profile) {
    return (
      <p>
        No has iniciado sesión. <Link to="/login">Inicia sesión</Link>
      </p>
    );
  }
  const { profile, security } = state;
  return (
    <section>
      <h1>Mi perfil</h1>
      <dl>
        <dt>Correo</dt>
        <dd>{profile.email}</dd>
        <dt>Rol</dt>
        <dd>{profile.role}</dd>
        <dt>Cuenta creada</dt>
        <dd>{new Date(profile.created_at).toLocaleString()}</dd>
        <dt>Segundo factor (MFA)</dt>
        <dd>
          {security.mfa_enabled ? "Activo" : "No configurado"}
          {security.mfa_required && " · obligatorio para tu rol"}
        </dd>
        {security.mfa_enabled && (
          <>
            <dt>Códigos de recuperación disponibles</dt>
            <dd>{security.recovery_codes_remaining}</dd>
          </>
        )}
      </dl>
      <form id="profile-form" name="profile" onSubmit={onSubmit} noValidate>
        <label htmlFor="profile-name">Nombre</label>
        <input id="profile-name" name="name" type="text" autoComplete="name" maxLength={100} defaultValue={profile.name} required />
        {message && <p role="status">{message}</p>}
        <button type="submit" disabled={busy}>Guardar</button>
      </form>
      <p>
        <Link to="/sessions">Mis sesiones</Link> · <Link to="/">Volver</Link>
      </p>
    </section>
  );
}
