import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { api, ApiError } from "../api/client.js";

// Registro de Clientes (T056; FR-001 a FR-005; U1). El formulario es un <form> con botón submit,
// email con autocomplete="username" y contraseña con autocomplete="new-password". Se permite pegar,
// sin autocomplete="off", sin readonly y sin maxlength inferior a 128: compatible con gestores.
export default function Register() {
  const navigate = useNavigate();
  const [errors, setErrors] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setErrors(null);
    try {
      await api("/auth/register", {
        method: "POST",
        body: { email: form.get("email"), name: form.get("name"), password: form.get("password") },
      });
      navigate("/login", { state: { registered: true } });
    } catch (err) {
      setErrors(err instanceof ApiError ? err : new ApiError(0, null));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-layout">
    <form id="register-form" name="register" method="post" onSubmit={onSubmit} noValidate>
      <h1>Crear cuenta de Cliente</h1>
      <label htmlFor="register-email">Correo (ficticio)</label>
      <input id="register-email" name="email" type="email" autoComplete="username" required />
      <label htmlFor="register-name">Nombre</label>
      <input id="register-name" name="name" type="text" autoComplete="name" maxLength={100} required />
      <label htmlFor="register-password">Contraseña (15 a 128 caracteres)</label>
      <input id="register-password" name="password" type="password" autoComplete="new-password" maxLength={128} required />
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
      <button type="submit" disabled={busy}>{busy ? "Creando…" : "Registrarse"}</button>
      <p className="auth-switch">¿Ya tienes cuenta? <Link to="/login">Inicia sesión</Link></p>
    </form>
    <aside className="auth-aside">
      <p className="finance-eyebrow">Al abrir tu cuenta recibes</p>
      <div className="bank-card bank-card--light" aria-hidden="true">
        <span className="bank-card__chip" />
        <strong>SecureFin</strong>
        <span className="bank-card__balance">$ 5.000.000 COP</span>
        <small>Saldo de bienvenida ficticio</small>
      </div>
      <ul>
        <li>Cuenta de ahorros en COP lista para transferir.</li>
        <li>Puedes abrir cuentas adicionales en COP o USD.</li>
        <li>Tu contraseña se valida contra una lista de contraseñas filtradas y se guarda con Argon2id.</li>
        <li>El rol siempre es Cliente: enviar <code>"role":"admin"</code> se rechaza (asignación masiva).</li>
      </ul>
    </aside>
    </div>
  );
}
