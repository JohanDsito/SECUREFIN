import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client.js";
import ConfirmButton from "../../components/ConfirmButton.jsx";
import { adminErrorMessage, fieldMessages, needsLogin } from "./errors.js";

// Bandeja de reinicios de MFA (T093; R11; FR-032–FR-035; contrato §4).
// 1. Abrir: el Administrador ya contactó al titular por un canal fuera de banda y lo registra.
// 2. El titular recibe un código de 8 caracteres en su correo y se lo lee al Administrador.
// 3. Autorizar: código del titular + TOTP actual del Administrador + confirmación del canal.
// El Administrador nunca ve secretos ni códigos de recuperación: el titular configura el MFA de nuevo.
// Los códigos tecleados solo viven en el formulario y se borran tras cada envío (éxito o error).
const STATUSES = [
  ["requested", "Solicitados"],
  ["pending_verification", "Pendientes de verificación"],
  ["authorized", "Autorizados"],
  ["cancelled", "Cancelados"],
  ["expired", "Caducados"],
];
const CHANNELS = [
  ["in_person", "En persona"],
  ["course_channel", "Canal oficial del curso"],
];
const channelLabel = (value) => CHANNELS.find(([v]) => v === value)?.[1] ?? value;

function ErrorNotice({ error }) {
  return (
    <div role="alert">
      <p>
        {adminErrorMessage(error)} {needsLogin(error) && <Link to="/login">Iniciar sesión</Link>}
      </p>
      {fieldMessages(error).length > 0 && (
        <ul>
          {fieldMessages(error).map((m) => (
            <li key={m.key}>{m.text}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function MfaResets() {
  const [status, setStatus] = useState("requested");
  const [state, setState] = useState({ loading: true, cases: null, error: null });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const load = useCallback(() => {
    setState((s) => ({ ...s, loading: true }));
    return api(`/admin/mfa-resets?status=${encodeURIComponent(status)}`)
      .then((data) => setState({ loading: false, cases: data.results, error: null }))
      .catch((error) => setState({ loading: false, cases: null, error }));
  }, [status]);

  useEffect(() => {
    load();
  }, [load]);

  async function run(action, success) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage({ ok: true, text: success });
      return true;
    } catch (error) {
      setMessage({ ok: false, error });
      return false;
    } finally {
      setBusy(false);
      load();
    }
  }

  if (state.error) {
    return (
      <section>
        <h1>Reinicios de MFA</h1>
        <ErrorNotice error={state.error} />
        <p>
          <Link to="/">Volver</Link>
        </p>
      </section>
    );
  }
  if (!state.cases) return <p role="status">Cargando…</p>;

  return (
    <section aria-busy={state.loading || busy}>
      <h1>Reinicios de MFA</h1>
      <p className="hint">
        Antes de abrir un caso, verifica la identidad del titular por un canal fuera de banda. Nunca autorices un
        caso solo porque conoces su nombre y su correo.
      </p>
      {busy && <p role="status">Procesando…</p>}
      {message?.ok && <p role="status">{message.text}</p>}
      {message && !message.ok && <ErrorNotice error={message.error} />}
      <label htmlFor="case-status">Estado </label>
      <select id="case-status" value={status} onChange={(e) => setStatus(e.target.value)}>
        {STATUSES.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
      {state.loading && <p role="status">Cargando…</p>}
      {state.cases.length === 0 ? (
        <p>No hay casos en este estado.</p>
      ) : (
        <ul>
          {state.cases.map((c) => (
            <CaseItem key={c.case_id} item={c} run={run} busy={busy} />
          ))}
        </ul>
      )}
      <p>
        <Link to="/admin/users">Usuarios</Link> · <Link to="/">Volver</Link>
      </p>
    </section>
  );
}

function CaseItem({ item, run, busy }) {
  const base = `/admin/mfa-resets/${encodeURIComponent(item.case_id)}`;
  const [channel, setChannel] = useState("in_person");

  async function onAuthorize(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const body = {
      verification_code: String(form.get("verification_code") ?? "").trim(),
      admin_totp_code: String(form.get("admin_totp_code") ?? "").trim(),
      channel_confirmed: form.get("channel_confirmed") === "on",
    };
    formElement.reset(); // los códigos no se conservan en el formulario, ni tras un error
    await run(
      () => api(`${base}/authorize`, { method: "POST", body }),
      "MFA reiniciado: sesiones del titular revocadas y aviso enviado a su buzón.",
    );
  }

  return (
    <li>
      <p>
        <strong>{item.target_email}</strong> · solicitado el {new Date(item.requested_at).toLocaleString()}
      </p>
      {item.status === "requested" && (
        <p>
          <label htmlFor={`channel-${item.case_id}`}>Canal fuera de banda </label>
          <select
            id={`channel-${item.case_id}`}
            value={channel}
            disabled={busy}
            onChange={(e) => setChannel(e.target.value)}
          >
            {CHANNELS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>{" "}
          <ConfirmButton
            label="Abrir caso"
            question={`¿Has contactado con ${item.target_email} por «${channelLabel(channel)}»? Se le enviará un código de 8 caracteres válido 10 minutos.`}
            confirmLabel="Sí, abrir caso"
            disabled={busy}
            onConfirm={() =>
              run(
                () => api(`${base}/open`, { method: "POST", body: { request_channel: channel } }),
                "Caso abierto: el titular recibirá un código de 8 caracteres (válido 10 minutos).",
              )
            }
          />
        </p>
      )}
      {item.status === "pending_verification" && (
        <form method="post" onSubmit={onAuthorize} aria-label={`Autorizar reinicio de ${item.target_email}`}>
          <label htmlFor={`code-${item.case_id}`}>Código que te lee el titular</label>
          <input
            id={`code-${item.case_id}`}
            name="verification_code"
            type="text"
            autoComplete="off"
            spellCheck={false}
            maxLength={16}
            required
          />
          <label htmlFor={`totp-${item.case_id}`}>Tu código TOTP actual</label>
          <input
            id={`totp-${item.case_id}`}
            name="admin_totp_code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
          />
          <label>
            <input name="channel_confirmed" type="checkbox" required /> Confirmo que recibí el código por el canal
            registrado
          </label>
          <button type="submit" disabled={busy}>
            Autorizar reinicio
          </button>
        </form>
      )}
      {(item.status === "requested" || item.status === "pending_verification") && (
        <ConfirmButton
          label="Cancelar caso"
          question={`¿Cancelar el caso de ${item.target_email}?`}
          confirmLabel="Sí, cancelar el caso"
          dismissLabel="No"
          disabled={busy}
          onConfirm={() => run(() => api(`${base}/cancel`, { method: "POST", body: {} }), "Caso cancelado.")}
        />
      )}
    </li>
  );
}
