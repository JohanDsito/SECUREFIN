// Fixture de Mailpit (T139; corrección U2): API REST autenticada a través de Nginx en
// https://127.0.0.1:8025 (CA de laboratorio vía NODE_EXTRA_CA_CERTS). Credenciales Basic Auth de
// MAILPIT_API_USER y MAILPIT_API_PASSWORD: si faltan, la prueba FALLA (nunca se omite).
// Prohibido imprimir o registrar tokens, URLs completas o cuerpos de correo, escribirlos en archivos
// o adjuntarlos al informe (U1). Los errores solo incluyen el código HTTP.

const MAILPIT_BASE = "https://127.0.0.1:8025/api/v1";

function authHeaders(extra = {}) {
  const user = process.env.MAILPIT_API_USER;
  const pass = process.env.MAILPIT_API_PASSWORD;
  if (!user || !pass) {
    throw new Error("MAILPIT_API_USER o MAILPIT_API_PASSWORD no están definidas: las E2E necesitan la API de Mailpit.");
  }
  return { Authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`, ...extra };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const mailpit = {
  /** GET /api/v1/messages y filtrado por destinatario y asunto. Devuelve el mensaje más reciente o null. */
  async findMessage({ to, subject }) {
    const res = await fetch(`${MAILPIT_BASE}/messages`, { headers: authHeaders() });
    if (!res.ok) throw new Error(`Mailpit respondió ${res.status} al listar mensajes`);
    const data = await res.json();
    return (
      (data.messages || []).find((msg) => {
        const matchTo = !to || (msg.To || []).some((r) => r.Address === to);
        const matchSubject = !subject || (msg.Subject || "").includes(subject);
        return matchTo && matchSubject;
      }) ?? null
    );
  },

  /** Igual que findMessage, pero espera a que el mailer lo entregue (sondeo cada segundo). */
  async waitForMessage(criteria, { timeoutMs = 30000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const msg = await this.findMessage(criteria);
      if (msg) return msg;
      await sleep(1000);
    }
    throw new Error("No llegó el correo esperado al buzón de laboratorio");
  },

  /** GET /api/v1/message/{ID} y extracción del fragmento #token= SOLO en memoria. */
  async extractToken(messageId) {
    const res = await fetch(`${MAILPIT_BASE}/message/${encodeURIComponent(messageId)}`, { headers: authHeaders() });
    if (!res.ok) throw new Error(`Mailpit respondió ${res.status} al leer un mensaje`);
    const msg = await res.json();
    const match = `${msg.Text || ""} ${msg.HTML || ""}`.match(/#token=([A-Za-z0-9_-]+)/);
    if (!match) throw new Error("El mensaje no contiene el fragmento #token=");
    return match[1];
  },

  /** DELETE /api/v1/messages con los IDs indicados. Nunca vacía el buzón completo. */
  async deleteMessages(ids) {
    if (!Array.isArray(ids) || ids.length === 0) return;
    const res = await fetch(`${MAILPIT_BASE}/messages`, {
      method: "DELETE",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ IDs: ids }),
    });
    if (!res.ok) throw new Error(`Mailpit respondió ${res.status} al borrar mensajes`);
  },
};
