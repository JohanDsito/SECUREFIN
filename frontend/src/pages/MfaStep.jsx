import { useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api/client.js";
import ConfirmButton from "../components/ConfirmButton.jsx";

// Segundo paso del login (T080; FR-008, FR-026, FR-029). Con la sesión pre_auth que dejó la
// contraseña, se envía un código TOTP o un código de recuperación. Ante cualquier fallo, el mismo
// mensaje genérico; si la fase pre_auth caducó (5 min), hay que volver a introducir la contraseña.
const GENERIC = "Credenciales inválidas o demasiados intentos. Inténtalo más tarde.";

// Reinicio administrativo (T093; R11 paso 1): solo desde esta fase pre_auth, es decir, tras validar la
// contraseña. La solicitud cierra la sesión pre_auth; un Administrador verificará la identidad por un
// canal fuera de banda y el titular recibirá un código en su correo que deberá leerle.
const RESET_REQUESTED =
  "Solicitud registrada. Un Administrador contactará contigo por un canal oficial para verificar tu identidad; " +
  "recibirás un código en tu correo que solo debes leerle a él. Después configurarás de nuevo el MFA.";

export default function MfaStep() {
  const navigate = useNavigate();
  const [useRecovery, setUseRecovery] = useState(false);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [resetRequested, setResetRequested] = useState(false);

  async function requestReset() {
    setBusy(true);
    setMessage(null);
    try {
      await api("/auth/login/mfa-reset-request", { method: "POST", body: {} });
      setResetRequested(true);
    } catch (error) {
      setMessage(
        error.status === 429
          ? "Has alcanzado el máximo de solicitudes de reinicio (3 cada 24 horas). Inténtalo más tarde."
          : "Tu verificación ha caducado. Vuelve a introducir tu contraseña para solicitar el reinicio.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (resetRequested) {
    return (
      <section>
        <h1>Reinicio de MFA solicitado</h1>
        <p role="status">{RESET_REQUESTED}</p>
      </section>
    );
  }

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
      <p>
        <ConfirmButton
          label="Perdí mi dispositivo y mis códigos"
          question={
            "Se cerrará esta sesión y un Administrador verificará tu identidad antes de reiniciar el MFA. " +
            "Tu contraseña no cambia. ¿Solicitar el reinicio?"
          }
          confirmLabel="Sí, solicitar reinicio"
          disabled={busy}
          onConfirm={requestReset}
        />
      </p>
    </form>
  );
}
