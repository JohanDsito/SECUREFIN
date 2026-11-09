// Fixture de Mailpit (T139): API REST autenticada a través de Nginx en https://127.0.0.1:8025.
// Prohibido imprimir o registrar tokens, URLs completas o cuerpos de correo (U1).

const MAILPIT_BASE = "https://127.0.0.1:8025/api/v1";

function getAuthHeaders() {
  const user = process.env.MAILPIT_API_USER;
  const pass = process.env.MAILPIT_API_PASSWORD;
  if (!user || !pass) {
    throw new Error(
      "MAILPIT_API_USER o MAILPIT_API_PASSWORD no están definidas. Las pruebas E2E requieren credenciales de Mailpit."
    );
  }
  const credentials = Buffer.from(`${user}:${pass}`).toString("base64");
  return {
    Authorization: `Basic ${credentials}`,
  };
}

export const mailpit = {
  /**
   * Busca mensajes en Mailpit filtrando por destinatario y asunto.
   */
  async findMessage({ to, subject }) {
    const res = await fetch(`${MAILPIT_BASE}/messages`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Error consultando mensajes de Mailpit: ${res.status}`);
    }
    const data = await res.json();
    const messages = data.messages || [];
    return messages.find((msg) => {
      const matchTo = !to || (msg.To && msg.To.some((recipient) => recipient.Address === to));
      const matchSubject = !subject || (msg.Subject && msg.Subject.includes(subject));
      return matchTo && matchSubject;
    });
  },

  /**
   * Extrae el token del enlace (#token=...) en memoria sin imprimirlo ni almacenarlo en disco.
   */
  async extractToken(messageId) {
    const res = await fetch(`${MAILPIT_BASE}/message/${messageId}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Error obteniendo mensaje de Mailpit: ${res.status}`);
    }
    const msg = await res.json();
    const textContent = `${msg.Text || ""} ${msg.HTML || ""}`;
    const tokenMatch = textContent.match(/#token=([a-zA-Z0-9_-]+)/);
    if (!tokenMatch) {
      throw new Error("No se encontró el fragmento #token= en el mensaje");
    }
    return tokenMatch[1];
  },

  /**
   * Elimina mensajes por ID o vacía el buzón si no se especifican IDs.
   */
  async deleteMessages(ids = []) {
    const headers = getAuthHeaders();
    if (ids.length === 0) {
      await fetch(`${MAILPIT_BASE}/messages`, {
        method: "DELETE",
        headers,
      });
    } else {
      for (const id of ids) {
        await fetch(`${MAILPIT_BASE}/message/${id}`, {
          method: "DELETE",
          headers,
        });
      }
    }
  },
};

