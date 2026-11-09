import { useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api/client.js";
import RecoveryCodes from "../components/RecoveryCodes.jsx";

// Alta de TOTP (T080; FR-024, FR-025, FR-031). Dos modos:
// - "login": alta obligatoria de Administrador o Auditor durante el login (sesión pre_auth, 10 min).
// - "self": alta o reconfiguración desde el perfil (sesión completa; reconfigurar pide la contraseña).
// El secreto y el QR (data: URI en <img>, admitido por la CSP) solo viven en el estado del componente.
const ENDPOINTS = {
  login: { setup: "/auth/login/enroll/setup", confirm: "/auth/login/enroll/confirm" },
  self: { setup: "/users/me/mfa/totp/setup", confirm: "/users/me/mfa/totp/confirm" },
};

export default function Enroll({ mode = "self", reconfigure = false }) {
  const navigate = useNavigate();
  const urls = ENDPOINTS[mode];
  const [setup, setSetup] = useState(null);
  const [codes, setCodes] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  async function start(event) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const body = reconfigure ? { password: new FormData(event.currentTarget).get("password") } : {};
      setSetup(await api(urls.setup, { method: "POST", body }));
    } catch (error) {
      if (error.status === 401) setMessage("La sesión caducó. Vuelve a iniciar sesión.");
      else if (error.code === "verification_failed") setMessage("La contraseña no es correcta.");
      else setMessage("No fue posible iniciar la configuración.");
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event) {
    event.preventDefault();
    const totp_code = new FormData(event.currentTarget).get("totp_code").trim();
    setBusy(true);
    setMessage(null);
    try {
      const result = await api(urls.confirm, { method: "POST", body: { totp_code } });
      setSetup(null); // el secreto deja de estar en memoria en cuanto se confirma
      setCodes(result.recovery_codes);
    } catch {
      setMessage("El código no es válido. Comprueba la hora de tu dispositivo e inténtalo de nuevo.");
    } finally {
      setBusy(false);
    }
  }

  if (codes) return <RecoveryCodes codes={codes} onDone={() => navigate("/")} />;

  if (!setup) {
    return (
      <form id="enroll-start" name="enroll-start" onSubmit={start} noValidate>
        <h1>{reconfigure ? "Reconfigurar" : "Configurar"} la verificación en dos pasos</h1>
        {mode === "login" && <p>Tu rol exige un segundo factor. Configúralo para continuar.</p>}
        {reconfigure && (
          <>
            <label htmlFor="enroll-password">Contraseña actual</label>
            <input id="enroll-password" name="password" type="password" autoComplete="current-password" maxLength={128} required />
          </>
        )}
        {message && <p role="alert">{message}</p>}
        <button type="submit" disabled={busy}>Generar código QR</button>
      </form>
    );
  }

  return (
    <section>
      <h1>Escanea el código QR</h1>
      <p>Usa una aplicación autenticadora (TOTP). Si no puedes escanearlo, introduce la clave manualmente.</p>
      <img src={setup.qr_svg_data_uri} alt="Código QR para tu aplicación autenticadora" width="220" height="220" />
      <p>
        Clave: <code>{setup.secret_base32.match(/.{1,4}/g).join(" ")}</code>
      </p>
      <form id="enroll-confirm" name="enroll-confirm" onSubmit={confirm} noValidate>
        <label htmlFor="enroll-code">Código de 6 dígitos que muestra la aplicación</label>
        <input id="enroll-code" name="totp_code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required />
        {message && <p role="alert">{message}</p>}
        <button type="submit" disabled={busy}>Confirmar</button>
      </form>
    </section>
  );
}
