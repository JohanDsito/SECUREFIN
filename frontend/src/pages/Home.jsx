import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { api } from "../api/client.js";

const ROLE_LABEL = { client: "Cliente", admin: "Administrador", auditor: "Auditor" };

const PILLARS = [
  { icon: "🔐", title: "Cifrado de extremo a extremo", text: "TLS 1.2/1.3 con certificado RSA-3072 e intercambio ECDHE. HTTP solo redirige a HTTPS." },
  { icon: "🧂", title: "Contraseñas con Argon2id", text: "Hash lento con salt aleatoria por usuario. Los secretos MFA se guardan con AES-256-GCM." },
  { icon: "📱", title: "Doble factor (TOTP)", text: "Obligatorio para Administradores y Auditores, con códigos de recuperación de un solo uso." },
  { icon: "🛡️", title: "Defensa en capas", text: "Nginx bastionado, rate limiting contra DoS y fuerza bruta, redes aisladas y auditoría inmutable." },
];

// Portada (T056). Sin sesión: presentación de la fintech. Con sesión `full`: centro de control.
export default function Home() {
  const remaining = useLocation().state?.recoveryCodesRemaining;
  const [state, setState] = useState({ loading: true, data: null });

  useEffect(() => {
    api("/auth/session")
      .then((data) => setState({ loading: false, data }))
      .catch(() => setState({ loading: false, data: null }));
  }, []);

  if (state.loading) return <p role="status">Cargando…</p>;

  if (!state.data) {
    return (
      <div className="landing">
        <section className="hero">
          <div className="hero__copy">
            <p className="finance-eyebrow">Banca digital simulada</p>
            <h1>Tu dinero ficticio, protegido como si fuera real.</h1>
            <p>
              SecureFin es una fintech de laboratorio: abre cuentas, transfiere fondos y consulta tus
              movimientos mientras cada capa del sistema aplica un control de ciberseguridad del curso.
            </p>
            <div className="hero__actions">
              <Link className="finance-button" to="/register">Abrir mi cuenta</Link>
              <Link className="hero__secondary" to="/login">Ya tengo cuenta →</Link>
            </div>
          </div>
          <div className="hero__card" aria-hidden="true">
            <div className="bank-card">
              <span className="bank-card__chip" />
              <strong>SecureFin</strong>
              <span className="bank-card__number">•••• •••• •••• 2026</span>
              <span className="bank-card__balance">$ 1.000.000 COP</span>
              <small>Saldo de demostración</small>
            </div>
            <ul className="hero__checks">
              <li>✔ HTTPS · TLS 1.3</li>
              <li>✔ MFA TOTP</li>
              <li>✔ 429 ante ráfagas</li>
            </ul>
          </div>
        </section>
        <section className="pillars" aria-label="Cómo te protegemos">
          {PILLARS.map((p) => (
            <article key={p.title}>
              <span aria-hidden="true">{p.icon}</span>
              <h2>{p.title}</h2>
              <p>{p.text}</p>
            </article>
          ))}
        </section>
        <section className="landing-cta">
          <div>
            <h2>¿Quieres ver los controles funcionando?</h2>
            <p>El Centro de seguridad comprueba en vivo cabeceras, TLS, cookies, inyección SQL y rate limiting.</p>
          </div>
          <Link className="finance-button" to="/seguridad">Abrir Centro de seguridad</Link>
        </section>
      </div>
    );
  }

  const { user, session } = state.data;
  const tiles =
    user.role === "client"
      ? [
          { to: "/finance", icon: "💳", title: "Mi dinero", text: "Saldos, cuentas y actividad" },
          { to: "/finance/transfer", icon: "↗", title: "Transferir", text: "Envía fondos ficticios" },
          { to: "/finance/activity", icon: "▤", title: "Movimientos", text: "Historial de operaciones" },
        ]
      : [];
  if (user.role === "admin") {
    tiles.push(
      { to: "/admin/finance/approvals", icon: "✅", title: "Aprobaciones", text: "Transferencias retenidas" },
      { to: "/admin/users", icon: "👥", title: "Usuarios", text: "Crear, cambiar rol, desactivar" },
      { to: "/admin/mfa-resets", icon: "🔁", title: "Reinicios de MFA", text: "Casos verificados" },
    );
  }
  if (user.role === "auditor") {
    tiles.push({ to: "/admin/finance/approvals", icon: "🔎", title: "Aprobaciones", text: "Consulta de solo lectura" });
  }
  tiles.push(
    { to: "/sessions", icon: "🖥", title: "Mis sesiones", text: "Dispositivos con acceso" },
    { to: "/profile", icon: "👤", title: "Perfil y MFA", text: "Datos y doble factor" },
    { to: "/seguridad", icon: "🛡️", title: "Centro de seguridad", text: "Controles en vivo" },
  );

  return (
    <section className="hub">
      <div className="hub__heading">
        <div>
          <p className="finance-eyebrow">{ROLE_LABEL[user.role] ?? user.role}</p>
          <h1>Hola, {user.name}</h1>
          <p>
            Sesión verificada en el servidor. Caduca por inactividad a las{" "}
            <strong>{new Date(session.idle_expires_at).toLocaleTimeString("es-CO")}</strong>
          </p>
        </div>
        <span className="hub__badge">Sesión segura · HttpOnly · SameSite=Strict</span>
      </div>
      {remaining !== undefined && (
        <p role="status">
          Has usado un código de recuperación. Te quedan {remaining}. Si perdiste tu dispositivo, reconfigura el MFA
          desde <Link to="/profile">tu perfil</Link>.
        </p>
      )}
      <div className="hub__grid">
        {tiles.map((t) => (
          <Link className="hub__tile" to={t.to} key={t.to + t.title}>
            <span aria-hidden="true">{t.icon}</span>
            <strong>{t.title}</strong>
            <small>{t.text}</small>
          </Link>
        ))}
      </div>
    </section>
  );
}
