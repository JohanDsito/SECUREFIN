import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, ApiError } from "../api/client.js";
import { takeFragmentToken } from "../lib/fragmentToken.js";

// Activación de cuentas creadas por un Administrador (T093; FR-021; contrato §6; R7; U1).
// - El token llega en el fragmento (#token=…): se lee al montar, history.replaceState lo borra de la
//   URL y del historial, y vive SOLO en el estado del componente. Nunca en storage, cookies, URL,
//   estado del router ni consola. Se descarta tras el envío (éxito o token inválido).
// - Formulario compatible con gestores de contraseñas: <form> con botón submit, type="password",
//   autocomplete="new-password", name/id estables, se permite pegar, sin autocomplete="off", sin
//   readonly y sin maxlength inferior a 128.
const INVALID_LINK = "El enlace no es válido o ha caducado. Pide a un Administrador que lo reenvíe.";

export default function Activate() {
  const [token, setToken] = useState(null);
  const [checked, setChecked] = useState(false);
  const [done, setDone] = useState(false);
  const [errors, setErrors] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const value = takeFragmentToken();
    if (value) setToken(value);
    setChecked(true);
  }, []);

  async function onSubmit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = form.get("password");
    if (password !== form.get("password_confirm")) {
      setErrors({ message: "Las contraseñas no coinciden.", fields: null });
      return;
    }
    setBusy(true);
    setErrors(null);
    try {
      await api("/auth/activate", { method: "POST", body: { token, password } });
      setToken(null);
      setDone(true);
    } catch (err) {
      const error = err instanceof ApiError ? err : new ApiError(0, null);
      if (error.code === "invalid_token") {
        setToken(null);
        setErrors({ message: INVALID_LINK, fields: null });
      } else {
        setErrors(error); // política de contraseñas: el enlace sigue sirviendo
      }
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <section>
        <h1>Cuenta activada</h1>
        <p role="status">
          Ya puedes <Link to="/login">iniciar sesión</Link>. Si tu rol lo exige, configurarás el segundo factor (MFA)
          antes de operar.
        </p>
      </section>
    );
  }

  return (
    <form id="activate-form" name="activate" method="post" onSubmit={onSubmit} noValidate aria-busy={busy}>
      <h1>Activa tu cuenta</h1>
      {checked && !token && !errors && <p role="alert">{INVALID_LINK}</p>}
      <label htmlFor="activate-password">Nueva contraseña (15 a 128 caracteres)</label>
      <input
        id="activate-password"
        name="password"
        type="password"
        autoComplete="new-password"
        maxLength={128}
        required
      />
      <label htmlFor="activate-password-confirm">Repite la contraseña</label>
      <input
        id="activate-password-confirm"
        name="password_confirm"
        type="password"
        autoComplete="new-password"
        maxLength={128}
        required
      />
      <p className="hint">Usa una frase larga. Puedes pegarla desde tu gestor de contraseñas.</p>
      {errors && (
        <div role="alert">
          <p>{errors.message}</p>
          {errors.fields && (
            <ul>
              {Object.entries(errors.fields).flatMap(([field, msgs]) =>
                (Array.isArray(msgs) ? msgs : [msgs]).map((m) => <li key={`${field}-${m}`}>{m}</li>),
              )}
            </ul>
          )}
        </div>
      )}
      <button type="submit" disabled={busy || !token}>
        {busy ? "Activando…" : "Activar cuenta"}
      </button>
    </form>
  );
}
