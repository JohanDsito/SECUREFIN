import { useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api/client.js";

// Segundo paso del login (T080; FR-008, FR-026, FR-029). Con la sesión pre_auth que dejó la
// contraseña, se envía un código TOTP o un código de recuperación. Ante cualquier fallo, el mismo
// mensaje genérico; si la fase pre_auth caducó (5 min), hay que volver a introducir la contraseña.
const GENERIC = "Credenciales inválidas o demasiados intentos. Inténtalo más tarde.";

export default function MfaStep() {
  const navigate = useNavigate();
  const [useRecovery, setUseRecovery] = useState(false);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    const value = new FormData(event.currentTarget).get("code").trim();
    setBusy(true);
    setMessage(null);
    try {
      const body = useRecovery ? { recovery_code: value } : { totp_code: value };
      const result = await api("/auth/login/mfa", { method: "POST", body });
      navigate("/", { state: { recoveryCodesRemaining: result.recovery_codes_remaining } });
    } catch (error) {
      setMessage(error.status === 400 ? "Revisa el formato del código." : GENERIC);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form id="mfa-form" name="mfa" method="post" onSubmit={onSubmit} noValidate>
      <h1>Verificación en dos pasos</h1>
      {useRecovery ? (
        <>
          <label htmlFor="mfa-code">Código de recuperación</label>
          <input id="mfa-code" name="code" type="text" autoComplete="off" spellCheck={false} maxLength={64} required />
        </>
      ) : (
        <>
          <label htmlFor="mfa-code">Código de tu aplicación autenticadora</label>
          <input
            id="mfa-code"
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
          />
        </>
      )}
      {message && <p role="alert">{message}</p>}
      <button type="submit" disabled={busy}>Verificar</button>
      <p>
        <button type="button" onClick={() => setUseRecovery((v) => !v)}>
          {useRecovery ? "Usar el código de la aplicación" : "Perdí mi dispositivo: usar un código de recuperación"}
        </button>
      </p>
    </form>
  );
}
