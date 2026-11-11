import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { api } from "../api/client.js";

// Inicio de sesión (T056; FR-005, FR-009; U1). Email con autocomplete="username" y contraseña con
// autocomplete="current-password". Ante cualquier fallo se muestra el mismo mensaje genérico.
const GENERIC = "Credenciales inválidas o demasiados intentos. Inténtalo más tarde.";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const [message, setMessage] = useState(location.state?.registered ? "Cuenta creada. Ya puedes iniciar sesión." : null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setMessage(null);
    try {
      const result = await api("/auth/login", {
        method: "POST",
        body: { email: form.get("email"), password: form.get("password") },
      });
      if (result.status === "authenticated") navigate("/");
      else if (result.status === "mfa_required") navigate("/login/mfa");
      else navigate("/login/enroll"); // mfa_enrollment_required
    } catch {
      setMessage(GENERIC);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-layout">
    <form id="login-form" name="login" method="post" onSubmit={onSubmit} noValidate>
      <h1>Iniciar sesión</h1>
      <label htmlFor="login-email">Correo</label>
      <input id="login-email" name="email" type="email" autoComplete="username" required />
      <label htmlFor="login-password">Contraseña</label>
      <input id="login-password" name="password" type="password" autoComplete="current-password" maxLength={128} required />
      {message && <p role="alert">{message}</p>}
      <button type="submit" disabled={busy}>{busy ? "Verificando…" : "Entrar"}</button>
      <p className="auth-switch">¿Aún no tienes cuenta? <Link to="/register">Ábrela gratis</Link></p>
    </form>
    <aside className="auth-aside">
      <p className="finance-eyebrow">Qué pasa al pulsar «Entrar»</p>
      <ol>
        <li><strong>TLS 1.3</strong> cifra la contraseña en el camino (Semana 2).</li>
        <li>El servidor la compara con un hash <strong>Argon2id</strong> con salt (Semana 1).</li>
        <li>Si eres Administrador o Auditor, pide tu código <strong>TOTP</strong> (Semana 4).</li>
        <li>Cualquier fallo da el <strong>mismo mensaje</strong>: no revela si el correo existe.</li>
        <li>Tras 5 fallos la cuenta entra en <strong>retraso progresivo</strong> y la IP en 429 (Semana 10).</li>
      </ol>
    </aside>
    </div>
  );
}
