import { useState } from "react";
import { useLocation, useNavigate } from "react-router";
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
      else setMessage("Se requiere el segundo factor (MFA) para continuar.");
    } catch {
      setMessage(GENERIC);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form id="login-form" name="login" method="post" onSubmit={onSubmit} noValidate>
      <h1>Iniciar sesión</h1>
      <label htmlFor="login-email">Correo</label>
      <input id="login-email" name="email" type="email" autoComplete="username" required />
      <label htmlFor="login-password">Contraseña</label>
      <input id="login-password" name="password" type="password" autoComplete="current-password" maxLength={128} required />
      {message && <p role="alert">{message}</p>}
      <button type="submit" disabled={busy}>Entrar</button>
    </form>
  );
}
