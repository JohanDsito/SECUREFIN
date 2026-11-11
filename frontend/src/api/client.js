// Cliente de la API (T045; R2, R3). Mismo origen: la cookie de sesión HttpOnly viaja sola y el SPA
// nunca maneja credenciales. Para métodos no seguros envía X-CSRFToken leído de la cookie CSRF.
const API = "/api/v1";
const CSRF_COOKIE = "__Host-sf_csrftoken";

function readCookie(name) {
  const match = document.cookie.split("; ").find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split("=")[1]) : null;
}

export class ApiError extends Error {
  constructor(status, error) {
    super(error?.message ?? "Error inesperado.");
    this.status = status;
    this.code = error?.code ?? "error";
    this.fields = error?.fields ?? null;
  }
}

async function ensureCsrf() {
  if (!readCookie(CSRF_COOKIE)) {
    await fetch(`${API}/auth/csrf`, { credentials: "same-origin" });
  }
  return readCookie(CSRF_COOKIE);
}

export async function api(path, { method = "GET", body, headers: requestHeaders = {} } = {}) {
  const headers = { Accept: "application/json", ...requestHeaders };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRFToken"] = await ensureCsrf();
  }
  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(response.status, data?.error);
  return data;
}
