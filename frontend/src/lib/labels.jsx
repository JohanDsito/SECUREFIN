// Formato y etiquetas en español compartidos por todas las pantallas (la API usa códigos en inglés).

export const ROLE_LABEL = { client: "Cliente", admin: "Administrador", auditor: "Auditor" };

export const STATUS = {
  completed: { label: "Completada", tone: "ok" },
  pending_approval: { label: "Pendiente de aprobación", tone: "warn" },
  rejected: { label: "Rechazada", tone: "bad" },
  active: { label: "Activa", tone: "ok" },
  frozen: { label: "Congelada", tone: "warn" },
  closed: { label: "Cerrada", tone: "bad" },
};

export const KIND_LABEL = {
  opening_credit: "Saldo de bienvenida",
  transfer: "Transferencia",
  reversal: "Reversión",
};

export function formatAmount(amountMinor, currency) {
  return new Intl.NumberFormat("es-CO", { style: "currency", currency, maximumFractionDigits: 2 }).format(
    amountMinor / 100,
  );
}

export function formatDate(value) {
  return new Date(value).toLocaleString("es-CO", { dateStyle: "medium", timeStyle: "short" });
}

export function StatusPill({ status }) {
  const s = STATUS[status] ?? { label: status, tone: "idle" };
  return <span className={`pill pill--${s.tone}`}>{s.label}</span>;
}

// "Mozilla/5.0 (Windows NT 10.0…) … Edg/154.0" → "Edge 154 · Windows"
export function describeUserAgent(ua) {
  if (!ua) return "Desconocido";
  const browser =
    [
      [/Edg\/(\d+)/, "Edge"],
      [/OPR\/(\d+)/, "Opera"],
      [/Firefox\/(\d+)/, "Firefox"],
      [/Chrome\/(\d+)/, "Chrome"],
      [/Version\/(\d+).*Safari/, "Safari"],
      [/curl\/([\d.]+)/, "curl"],
    ]
      .map(([re, name]) => {
        const m = ua.match(re);
        return m ? `${name} ${m[1]}` : null;
      })
      .find(Boolean) ?? "Navegador";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Android/.test(ua)
      ? "Android"
      : /iPhone|iPad/.test(ua)
        ? "iOS"
        : /Mac OS/.test(ua)
          ? "macOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return os ? `${browser} · ${os}` : browser;
}
