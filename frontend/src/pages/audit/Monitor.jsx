import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client.js";

// Panel de monitoreo en vivo (US6; contrato §5). Solo el Auditor con MFA puede leer la auditoría:
// el servidor responde 403 a cualquier otro rol. El panel solo lee; no hay acciones de edición.
const REFRESH_MS = 3000;

const EVENT_LABEL = {
  account_registered: "Cuenta registrada",
  account_activated: "Cuenta activada",
  activation_sent: "Enlace de activación enviado",
  account_created_by_admin: "Cuenta creada por un Administrador",
  account_deactivated: "Cuenta desactivada",
  account_reactivated: "Cuenta reactivada",
  role_changed: "Rol cambiado",
  login_succeeded: "Inicio de sesión correcto",
  login_failed: "Inicio de sesión fallido",
  logout: "Cierre de sesión",
  session_expired: "Sesión caducada",
  sessions_revoked: "Sesiones revocadas",
  mfa_enabled: "MFA activado",
  mfa_disabled: "MFA desactivado",
  mfa_reconfigured: "MFA reconfigurado",
  totp_rejected: "Código TOTP rechazado",
  recovery_code_used: "Código de recuperación usado",
  recovery_codes_regenerated: "Códigos de recuperación regenerados",
  mfa_reset_requested: "Reinicio de MFA solicitado",
  mfa_reset_case_opened: "Caso de reinicio de MFA abierto",
  mfa_reset_authorized: "Reinicio de MFA autorizado",
  mfa_reset_cancelled: "Reinicio de MFA cancelado",
  password_reset_requested: "Recuperación de contraseña solicitada",
  password_reset_completed: "Contraseña restablecida",
  password_changed: "Contraseña cambiada",
  email_delivery_failed: "Fallo al enviar correo",
  throttle_account_delay: "Retraso aplicado a una cuenta",
  throttle_ip_limited: "IP frenada por límite",
  credential_stuffing_suspected: "Sospecha de relleno de credenciales",
  authz_denied: "Acceso denegado",
  finance_account_opened: "Cuenta financiera abierta",
  finance_account_welcome_credited: "Saldo de bienvenida",
  finance_transfer_created: "Transferencia creada",
  finance_transfer_completed: "Transferencia completada",
  finance_transfer_rejected: "Transferencia rechazada",
  finance_approval_decided: "Decisión de aprobación",
  finance_limit_changed: "Límite financiero cambiado",
  finance_risk_alert: "Alerta de riesgo",
  finance_card_created: "Tarjeta creada",
  finance_card_status_changed: "Estado de tarjeta cambiado",
  bootstrap_admin_executed: "Primer Administrador creado",
  break_glass_executed: "Acceso de emergencia usado",
};

const REASON_LABEL = {
  invalid_credentials: "credenciales inválidas",
  throttled: "rechazado sin evaluar (cuenta en retraso)",
  invalid_totp: "código TOTP incorrecto",
  invalid_recovery_code: "código de recuperación incorrecto",
  decryption_failed: "secreto TOTP alterado",
  invalid_code: "código incorrecto",
  enrollment: "alta de MFA fallida",
  object: "recurso ajeno (posible IDOR)",
  function: "función no permitida para el rol",
  mfa_changed: "cambio de MFA",
  role_changed: "cambio de rol",
  account_deactivated: "cuenta desactivada",
  user_revoked_session: "cerrada por el usuario",
  idle: "inactividad",
  absolute: "tiempo máximo",
  admin_rejected: "rechazada por un Administrador",
  revalidation_failed: "falló la revalidación",
};

const OUTCOME_LABEL = { success: "Éxito", failure: "Fallo", denied: "Denegado" };
const ROLE_LABEL = { client: "Cliente", admin: "Administrador", auditor: "Auditor" };

const CARDS = [
  {
    key: "login_failed",
    label: "Inicios de sesión fallidos",
    hint: "Contraseñas o códigos MFA incorrectos",
    types: ["login_failed", "totp_rejected"],
    tone: "warn",
  },
  {
    key: "throttled",
    label: "Frenados por límite",
    hint: "Retrasos por cuenta y 429 por IP en Django",
    types: ["throttle_account_delay", "throttle_ip_limited"],
    tone: "alert",
  },
  {
    key: "authz",
    label: "Accesos denegados",
    hint: "Intentos de IDOR o de funciones de otro rol",
    types: ["authz_denied"],
    tone: "alert",
  },
  {
    key: "stuffing",
    label: "Relleno de credenciales",
    hint: "Una IP falló contra 10 o más cuentas",
    types: ["credential_stuffing_suspected"],
    tone: "critical",
  },
  {
    key: "ok",
    label: "Inicios de sesión correctos",
    hint: "Contraseña y, si aplica, MFA válidos",
    types: ["login_succeeded"],
    tone: "ok",
  },
  {
    key: "finance",
    label: "Operaciones financieras",
    hint: "Transferencias, aprobaciones y cuentas",
    prefix: "finance_",
    tone: "info",
  },
];

const OUTCOME_FILTERS = [
  { value: "", label: "Todos" },
  { value: "failure", label: "Fallidos" },
  { value: "denied", label: "Denegados" },
  { value: "success", label: "Exitosos" },
];

function cardCount(card, byType) {
  if (!byType) return 0;
  if (card.prefix) {
    return Object.entries(byType)
      .filter(([type]) => type.startsWith(card.prefix))
      .reduce((sum, [, n]) => sum + n, 0);
  }
  return card.types.reduce((sum, type) => sum + (byType[type] ?? 0), 0);
}

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatAmount(minor, currency) {
  try {
    return new Intl.NumberFormat("es-CO", { style: "currency", currency, maximumFractionDigits: 0 }).format(minor / 100);
  } catch {
    return `${minor / 100} ${currency}`;
  }
}

function eventDetail(event) {
  const m = event.metadata ?? {};
  const parts = [];
  if (m.reason) parts.push(REASON_LABEL[m.reason] ?? m.reason);
  if (m.stage && m.stage !== "password") parts.push(`etapa: ${m.stage}`);
  if (m.scope) parts.push(`límite: ${m.scope}`);
  if (m.delay_seconds) parts.push(`espera de ${m.delay_seconds} s`);
  if (m.failures) parts.push(`${m.failures} fallos seguidos`);
  if (m.distinct_identifiers) parts.push(`${m.distinct_identifiers} cuentas distintas`);
  if (m.method && m.path) parts.push(`${m.method} ${m.path}`);
  if (m.amount_minor && m.currency) parts.push(formatAmount(m.amount_minor, m.currency));
  if (m.decision) parts.push(m.decision === "approved" ? "aprobada" : "rechazada");
  if (m.from_role && m.to_role) parts.push(`${ROLE_LABEL[m.from_role] ?? m.from_role} → ${ROLE_LABEL[m.to_role] ?? m.to_role}`);
  if (m.mfa_method) parts.push(`MFA: ${m.mfa_method}`);
  return parts.join(" · ");
}

export default function Monitor() {
  const [minutes, setMinutes] = useState(15);
  const [outcome, setOutcome] = useState("");
  const [eventType, setEventType] = useState("");
  const [page, setPage] = useState(1);
  const [paused, setPaused] = useState(false);
  const [summary, setSummary] = useState(null);
  const [events, setEvents] = useState(null);
  const [types, setTypes] = useState([]);
  const [status, setStatus] = useState("loading"); // loading | live | error | forbidden
  const [updatedAt, setUpdatedAt] = useState(null);
  const seen = useRef(new Set());
  const [fresh, setFresh] = useState(new Set());

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    if (outcome) params.set("outcome", outcome);
    if (eventType) params.set("event_type", eventType);
    if (page > 1) params.set("page", String(page));
    const query = params.toString();
    try {
      const [nextSummary, nextEvents] = await Promise.all([
        api(`/audit/summary?minutes=${minutes}`),
        api(`/audit/events${query ? `?${query}` : ""}`),
      ]);
      const firstLoad = seen.current.size === 0;
      const newIds = new Set();
      for (const event of nextEvents.results) {
        if (!seen.current.has(event.id)) {
          if (!firstLoad) newIds.add(event.id);
          seen.current.add(event.id);
        }
      }
      setFresh(newIds);
      setSummary(nextSummary);
      setEvents(nextEvents);
      setUpdatedAt(new Date());
      setStatus("live");
    } catch (error) {
      setStatus(error.status === 401 || error.status === 403 ? "forbidden" : "error");
    }
  }, [minutes, outcome, eventType, page]);

  useEffect(() => {
    api("/audit/event-types").then(setTypes).catch(() => setTypes([]));
  }, []);

  useEffect(() => {
    if (status === "forbidden") return undefined;
    let timer;
    let alive = true;
    async function tick() {
      if (!paused && document.visibilityState === "visible") await load();
      if (alive) timer = setTimeout(tick, REFRESH_MS);
    }
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [load, paused, status]);

  if (status === "forbidden") {
    return (
      <section className="finance-page monitor">
        <Link to="/" className="finance-back-link">← Volver a inicio</Link>
        <p className="finance-eyebrow">Auditoría · solo lectura</p>
        <h1>Monitoreo de seguridad</h1>
        <div className="finance-notice" role="alert">
          <strong>Acceso solo para el rol Auditor</strong>
          <span>
            Inicia sesión con una cuenta de Auditor que haya completado el MFA. El Administrador no ve este
            panel a propósito: quien administra no audita sus propias acciones.
          </span>
        </div>
      </section>
    );
  }

  const timeline = summary?.timeline ?? [];
  const peak = Math.max(1, ...timeline.map((b) => b.success + b.failure + b.denied));

  return (
    <section className="finance-page monitor">
      <Link to="/" className="finance-back-link">← Volver a inicio</Link>
      <div className="monitor-head">
        <div>
          <p className="finance-eyebrow">Auditoría · solo lectura · rol Auditor</p>
          <h1>Monitoreo de seguridad</h1>
          <p className="monitor-sub">Eventos de seguridad de la aplicación en tiempo real. Se actualiza cada 3 segundos.</p>
        </div>
        <div className="monitor-controls">
          <span className={`monitor-live monitor-live--${paused ? "paused" : status}`} role="status">
            <span aria-hidden="true" />
            {paused
              ? "En pausa"
              : status === "live"
                ? `En vivo · ${updatedAt ? formatTime(updatedAt) : ""}`
                : status === "error"
                  ? "Sin conexión con el servidor"
                  : "Conectando…"}
          </span>
          <button type="button" className="monitor-btn" onClick={() => setPaused((p) => !p)}>
            {paused ? "Reanudar" : "Pausar"}
          </button>
          <label className="monitor-select">
            <span>Ventana</span>
            <select id="monitor-window" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
              <option value={5}>Últimos 5 min</option>
              <option value={15}>Últimos 15 min</option>
              <option value={60}>Última hora</option>
            </select>
          </label>
        </div>
      </div>

      <div className="monitor-cards">
        {CARDS.map((card) => {
          const n = cardCount(card, summary?.by_type);
          const active = n > 0 && card.tone !== "ok" && card.tone !== "info";
          return (
            <div key={card.key} className={`monitor-card monitor-card--${card.tone}${active ? " is-active" : ""}`}>
              <span className="monitor-card__label">{card.label}</span>
              <strong className="monitor-card__value">{summary ? n : "–"}</strong>
              <small>{active ? "Atención · " : ""}{card.hint}</small>
            </div>
          );
        })}
      </div>

      <div className="monitor-grid">
        <div className="monitor-panel">
          <div className="monitor-panel__head">
            <h2>Actividad en el tiempo</h2>
            <div className="monitor-legend" aria-hidden="true">
              <span className="lg lg--denied">Denegado</span>
              <span className="lg lg--failure">Fallo</span>
              <span className="lg lg--success">Éxito</span>
            </div>
          </div>
          <div
            className="monitor-timeline"
            role="img"
            aria-label={`Eventos por ${summary?.bucket_minutes ?? 1} minuto(s): ${summary?.by_outcome?.denied ?? 0} denegados, ${summary?.by_outcome?.failure ?? 0} fallidos y ${summary?.by_outcome?.success ?? 0} exitosos en la ventana`}
          >
            {timeline.map((bucket) => {
              const total = bucket.success + bucket.failure + bucket.denied;
              return (
                <div key={bucket.start} className="monitor-bar" title={`${formatTime(bucket.start)} · ${total} eventos`}>
                  <span className="seg seg--success" style={{ height: `${(bucket.success / peak) * 100}%` }} />
                  <span className="seg seg--failure" style={{ height: `${(bucket.failure / peak) * 100}%` }} />
                  <span className="seg seg--denied" style={{ height: `${(bucket.denied / peak) * 100}%` }} />
                </div>
              );
            })}
          </div>
          <div className="monitor-axis">
            <span>{timeline[0] ? formatTime(timeline[0].start) : ""}</span>
            <span>ahora</span>
          </div>
          <p className="monitor-totals">
            {summary
              ? `${summary.total} eventos en la ventana: ${summary.by_outcome.denied} denegados, ${summary.by_outcome.failure} fallidos y ${summary.by_outcome.success} exitosos.`
              : "Cargando…"}
          </p>
        </div>

        <div className="monitor-panel">
          <div className="monitor-panel__head"><h2>Orígenes con más fallos</h2></div>
          {summary?.top_sources?.length ? (
            <ol className="monitor-sources">
              {summary.top_sources.map((s) => (
                <li key={s.source_ip}>
                  <span className="mono">{s.source_ip}</span>
                  <strong>{s.count}</strong>
                </li>
              ))}
            </ol>
          ) : (
            <p className="monitor-empty">Sin fallos ni denegaciones en la ventana.</p>
          )}
          <div className="finance-notice monitor-note" role="note">
            <strong>¿Y el ataque DoS?</strong>
            <span>
              Nginx descarta la inundación HTTP con 429 antes de que llegue a Django, así que no aparece aquí:
              se ve en los logs de Nginx. Que este panel siga respondiendo durante el ataque es la prueba.
            </span>
          </div>
        </div>
      </div>

      <div className="monitor-panel">
        <div className="monitor-panel__head monitor-panel__head--wrap">
          <h2>Eventos recientes</h2>
          <div className="monitor-filters">
            <div className="monitor-chips" role="group" aria-label="Filtrar por resultado">
              {OUTCOME_FILTERS.map((f) => (
                <button
                  key={f.value || "all"}
                  type="button"
                  className={`monitor-chip${outcome === f.value ? " is-on" : ""}`}
                  aria-pressed={outcome === f.value}
                  onClick={() => {
                    setOutcome(f.value);
                    setPage(1);
                  }}
                >
                  {f.label}
                </button>
              ))}
            </div>
            <label className="monitor-select">
              <span>Tipo</span>
              <select
                id="monitor-type"
                value={eventType}
                onChange={(e) => {
                  setEventType(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">Todos los tipos</option>
                {types.map((t) => (
                  <option key={t} value={t}>{EVENT_LABEL[t] ?? t}</option>
                ))}
              </select>
            </label>
          </div>
        </div>

        <div className="finance-table-wrap">
          <table className="monitor-table">
            <thead>
              <tr>
                <th>Hora</th>
                <th>Evento</th>
                <th>Resultado</th>
                <th>Rol</th>
                <th>IP de origen</th>
                <th>Detalle</th>
              </tr>
            </thead>
            <tbody>
              {events?.results?.length ? (
                events.results.map((event) => (
                  <tr key={event.id} className={fresh.has(event.id) ? "is-new" : undefined}>
                    <td className="mono">{formatTime(event.occurred_at)}</td>
                    <td>
                      <span>{EVENT_LABEL[event.event_type] ?? event.event_type}</span>
                      <small className="mono">{event.event_type}</small>
                    </td>
                    <td><span className={`monitor-outcome monitor-outcome--${event.outcome}`}>{OUTCOME_LABEL[event.outcome] ?? event.outcome}</span></td>
                    <td>{ROLE_LABEL[event.actor_role] ?? "—"}</td>
                    <td className="mono">{event.source_ip ?? "—"}</td>
                    <td>{eventDetail(event) || "—"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="monitor-empty">
                    {events ? "No hay eventos con estos filtros." : "Cargando eventos…"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {events && events.pages > 1 && (
          <div className="monitor-pager">
            <button type="button" className="monitor-btn" disabled={!events.previous} onClick={() => setPage(events.previous)}>
              ← Más recientes
            </button>
            <span>Página {events.page} de {events.pages} · {events.count} eventos</span>
            <button type="button" className="monitor-btn" disabled={!events.next} onClick={() => setPage(events.next)}>
              Más antiguos →
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
