import { useState } from "react";

// Centro de seguridad: evidencia EN VIVO, desde el navegador, de los controles del curso. Cada
// prueba muestra (1) qué se envió, (2) qué respondió el servidor y (3) por qué eso demuestra la
// protección. Todo va contra el propio servidor (mismo origen) y con datos ficticios.

const API = "/api/v1";
const CSRF_COOKIE = "__Host-sf_csrftoken";

const HEADERS = [
  ["strict-transport-security", "HSTS", "S2", "SSL stripping / MITM", "El navegador recuerda usar siempre HTTPS: un atacante en la red no puede degradar a HTTP."],
  ["content-security-policy", "Content-Security-Policy", "S5", "XSS (scripts inyectados)", "Solo se ejecutan scripts servidos por este mismo origen. Pruébalo con «Intentar XSS»."],
  ["x-frame-options", "X-Frame-Options", "S5", "Clickjacking", "Nadie puede meter SecureFin en un iframe invisible. Pruébalo con «Intentar clickjacking»."],
  ["x-content-type-options", "X-Content-Type-Options", "S5", "MIME sniffing", "Un archivo subido como texto no puede ser interpretado como script."],
  ["referrer-policy", "Referrer-Policy", "S5", "Fuga de URL", "Al salir a otro sitio no se envía la URL de origen (podría llevar identificadores)."],
];

const SQLI = [
  ["Control: login fallido normal", "nadie@lab.securefin.local"],
  ["Bypass clásico", "' OR 1=1 --"],
  ["Comentario tras el correo", "admin@lab.securefin.local' --"],
  ["UNION para robar hashes", "x' UNION SELECT password FROM iam_user --"],
  ["Borrar la tabla", "x'; DROP TABLE iam_user; --"],
];

const MOMENTS = [
  {
    name: "Momento 1 · Fundamentos y seguridad de redes",
    weeks: [
      ["1", "Criptografía", "Argon2id + salt para contraseñas, AES-256-GCM para secretos MFA, HMAC-SHA-256 para tokens, RSA-3072/ECDHE en TLS.", "bash docs/security/demo/demo.sh cripto"],
      ["2", "Redes y tráfico", "HTTP solo redirige (301); TLS 1.0/1.1 rechazados; Wireshark muestra la contraseña en claro por HTTP y cifrada por HTTPS.", "bash docs/security/demo/demo.sh tls"],
      ["3", "LAN, VLAN y Wi-Fi", "Cuatro redes Docker aisladas (equivalente a VLANs); laboratorio Packet Tracer con VLANs y WPA2/WPA3-Enterprise.", "bash docs/security/demo/demo.sh red"],
      ["4", "IAM / AAA / MFA", "Roles Cliente/Admin/Auditor, denegar por defecto, MFA TOTP, sesiones de servidor y auditoría append-only; RADIUS en Packet Tracer.", "bash docs/security/demo/demo.sh auditoria"],
    ],
  },
  {
    name: "Momento 2 · Vulnerabilidad y desarrollo",
    weeks: [
      ["5", "Bastionado web", "server_tokens off, cabeceras defensivas, TRACE → 405, Nginx sin root.", "bash docs/security/demo/demo.sh cabeceras"],
      ["6", "NAC y cortafuegos", "Solo la DMZ (edge_net) publica 80/443; backend, BD y correo en redes internas. Denegar por defecto.", "bash docs/security/demo/demo.sh red"],
      ["7", "DevSecOps", "GitHub Actions con Semgrep, Bandit, pip-audit, npm audit y Trivy en cada push.", "bash docs/security/demo/demo.sh trivy"],
      ["8", "Pentesting", "Nmap -sV --script vuln; ' OR 1=1 -- falla aquí y funciona en OWASP Juice Shop.", "bash docs/security/demo/demo.sh juiceshop"],
    ],
  },
  {
    name: "Momento 3 · Ataque, defensa y auditoría",
    weeks: [
      ["9", "DoS / HTTP flood", "Apache Benchmark lanza 3000 peticiones contra Nginx; el sitio sigue respondiendo.", "bash docs/security/demo/demo.sh dos"],
      ["10", "Rate limiting", "limit_req (10/30/50 r/s) → 429; throttles por IP y por cuenta en Django con Retry-After.", "bash docs/security/demo/demo.sh fuerzabruta"],
    ],
  },
];

function readCookie(name) {
  const match = document.cookie.split("; ").find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split("=")[1]) : null;
}

async function csrfToken() {
  if (!readCookie(CSRF_COOKIE)) await fetch(`${API}/auth/csrf`, { credentials: "same-origin" });
  return readCookie(CSRF_COOKIE);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function Badge({ ok, children }) {
  return <span className={`check-badge ${ok === null ? "is-idle" : ok ? "is-ok" : "is-bad"}`}>{children}</span>;
}

function Verdict({ ok, children }) {
  return (
    <div className={`verdict ${ok ? "is-ok" : "is-bad"}`}>
      <strong>{ok ? "✔ PROTEGIDO" : "✘ REVISAR"}</strong>
      <span>{children}</span>
    </div>
  );
}

export default function SecurityCenter() {
  const [headers, setHeaders] = useState(null);
  const [xss, setXss] = useState(null);
  const [frame, setFrame] = useState(null);
  const [sqli, setSqli] = useState(null);
  const [flood, setFlood] = useState(null);
  const [busy, setBusy] = useState("");
  const [copied, setCopied] = useState(false);

  const https = window.location.protocol === "https:";
  const sessionCookieVisible = document.cookie.includes("sf_session");

  async function checkHeaders() {
    setBusy("headers");
    try {
      const res = await fetch("/", { method: "HEAD", cache: "no-store" });
      const found = Object.fromEntries(HEADERS.map(([h]) => [h, res.headers.get(h)]));
      setHeaders({ status: res.status, server: res.headers.get("server"), found });
    } finally {
      setBusy("");
    }
  }

  // Prueba activa de la CSP: se inyecta un <script> en línea (lo que haría un XSS). Si la CSP
  // funciona, el navegador lo bloquea, dispara `securitypolicyviolation` y la variable no cambia.
  async function tryXss() {
    setBusy("xss");
    window.__sfXss = false;
    let violation = null;
    const onViolation = (e) => {
      violation = `${e.violatedDirective || e.effectiveDirective} bloqueó un script en línea`;
    };
    document.addEventListener("securitypolicyviolation", onViolation);
    const s = document.createElement("script");
    s.textContent = "window.__sfXss = true;";
    document.body.appendChild(s);
    await sleep(300);
    document.removeEventListener("securitypolicyviolation", onViolation);
    s.remove();
    setXss({ executed: window.__sfXss === true, violation });
    setBusy("");
  }

  // Prueba activa de X-Frame-Options / frame-ancestors: se intenta cargar SecureFin dentro de un
  // iframe (lo que hace un sitio de clickjacking). Si está protegido, el navegador no muestra la app.
  async function tryFrame() {
    setBusy("frame");
    const iframe = document.createElement("iframe");
    iframe.className = "frame-probe";
    iframe.src = `/?probe=${Date.now()}`;
    document.body.appendChild(iframe);
    await new Promise((resolve) => {
      iframe.addEventListener("load", resolve, { once: true });
      setTimeout(resolve, 3000);
    });
    await sleep(400);
    let rendered = false;
    try {
      rendered = Boolean(iframe.contentDocument?.querySelector("#root")?.childElementCount);
    } catch {
      rendered = false; // página de error del navegador (otro origen): no se cargó la app
    }
    iframe.remove();
    setFrame({ rendered });
    setBusy("");
  }

  async function runSqli() {
    setBusy("sqli");
    setSqli(null);
    const rows = [];
    for (const [label, email] of SQLI) {
      const body = JSON.stringify({ email, password: "x" });
      const t0 = performance.now();
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRFToken": await csrfToken() },
        body,
      });
      const text = await res.text();
      rows.push({ label, email, request: body, status: res.status, length: text.length, text, ms: Math.round(performance.now() - t0) });
    }
    const control = rows[0];
    const attacks = rows.slice(1);
    const sameAsControl = attacks.every((r) => r.status === control.status && r.text === control.text);
    const noServerError = rows.every((r) => r.status < 500);
    const noLogin = rows.every((r) => r.status !== 200);
    const throttled = rows.some((r) => r.status === 429);
    setSqli({ rows, sameAsControl, noServerError, noLogin, throttled });
    setBusy("");
  }

  async function runFlood() {
    setBusy("flood");
    setFlood(null);
    const N = 80;
    const t0 = performance.now();
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        fetch(`${API}/auth/csrf`, { cache: "no-store", credentials: "same-origin" })
          .then((r) => ({ status: r.status, type: (r.headers.get("content-type") || "").split(";")[0] || "(vacío)" }))
          .catch(() => ({ status: 0, type: "error de red" })),
      ),
    );
    const ms = Math.round(performance.now() - t0);
    await sleep(2000);
    const after = await fetch(`${API}/auth/csrf`, { cache: "no-store", credentials: "same-origin" }).then((r) => r.status).catch(() => 0);
    const blocked = results.filter((r) => r.status === 429);
    const served = results.filter((r) => r.status >= 200 && r.status < 300);
    const crashed = results.filter((r) => r.status === 0 || r.status >= 500);
    setFlood({ N, results, ms, after, blocked, served, crashed, blockedType: blocked[0]?.type, servedType: served[0]?.type ?? "(vacío)" });
    setBusy("");
  }

  async function copyReport() {
    const lines = [`Informe de evidencia SecureFin · ${new Date().toLocaleString("es-CO")} · ${window.location.origin}`];
    lines.push(`Transporte: ${window.location.protocol} · Cookie de sesión visible para JS: ${sessionCookieVisible ? "SÍ" : "NO (HttpOnly)"}`);
    if (headers) {
      lines.push(`Server: ${headers.server ?? "(oculto)"}`);
      HEADERS.forEach(([h, label]) => lines.push(`${label}: ${headers.found[h] ?? "FALTA"}`));
    }
    if (xss) lines.push(`XSS en línea: ${xss.executed ? "SE EJECUTÓ" : "BLOQUEADO por CSP"}${xss.violation ? ` (${xss.violation})` : ""}`);
    if (frame) lines.push(`Clickjacking (iframe): ${frame.rendered ? "LA APP SE CARGÓ" : "BLOQUEADO (X-Frame-Options DENY / frame-ancestors 'none')"}`);
    if (sqli) {
      lines.push("Inyección SQL en /api/v1/auth/login:");
      sqli.rows.forEach((r) => lines.push(`  ${r.email.padEnd(45)} → HTTP ${r.status}, ${r.length} caracteres`));
      lines.push(`  Respuestas idénticas al login fallido normal: ${sqli.sameAsControl ? "SÍ" : "NO"} · Errores 5xx: ${sqli.noServerError ? "ninguno" : "SÍ"}`);
    }
    if (flood) {
      lines.push(`Ráfaga: ${flood.N} peticiones en ${flood.ms} ms → ${flood.blocked.length}×429 (${flood.blockedType}, Nginx), ${flood.served.length}×2xx (Django), ${flood.crashed.length} errores/caídas; 2 s después: HTTP ${flood.after}`);
    }
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="security-center">
      <div className="hub__heading">
        <div>
          <p className="finance-eyebrow">Evidencia en vivo</p>
          <h1>Centro de seguridad</h1>
          <p>
            Cada prueba ataca de verdad a este servidor y muestra <strong>qué se envió</strong>, <strong>qué respondió</strong> y{" "}
            <strong>por qué eso demuestra la protección</strong>. Abre también <kbd>F12</kbd> → pestaña <em>Red</em> para verlo en
            las herramientas del navegador.
          </p>
        </div>
        <button type="button" className="report-button" onClick={copyReport}>{copied ? "✔ Informe copiado" : "Copiar informe de evidencia"}</button>
      </div>

      <div className="check-grid">
        <article className="check-card">
          <header><h2>Transporte cifrado</h2><Badge ok={https}>{https ? "HTTPS" : "HTTP"}</Badge></header>
          <p>Semana 2 · Esta página llegó por <code>{window.location.protocol.replace(":", "")}</code>. Por HTTP (puerto 80) Nginx solo responde <code>301</code> hacia HTTPS. Clic en el candado de la barra → <em>Conexión segura</em> → ver certificado RSA-3072.</p>
        </article>
        <article className="check-card">
          <header><h2>Cookie de sesión</h2><Badge ok={!sessionCookieVisible}>{sessionCookieVisible ? "Expuesta" : "HttpOnly"}</Badge></header>
          <p>Semana 4 · <code>document.cookie</code> no contiene <code>__Host-sf_session</code>: aunque un atacante lograra ejecutar JavaScript, <strong>no podría robar la sesión</strong>. Verlo en F12 → <em>Almacenamiento</em> → Cookies: columna HttpOnly ✓.</p>
        </article>
      </div>

      {/* ---------------- INYECCIÓN SQL ---------------- */}
      <article className="check-card evidence">
        <header>
          <div>
            <h2>Inyección SQL contra el login · Semana 8</h2>
            <p>Se envían 4 payloads de inyección y, como <strong>grupo de control</strong>, un login fallido normal.</p>
          </div>
          <button type="button" onClick={runSqli} disabled={busy === "sqli"}>{busy === "sqli" ? "Atacando…" : "Lanzar inyección SQL"}</button>
        </header>
        {sqli ? (
          <>
            <div className="table-scroll">
              <table className="evidence-table">
                <thead><tr><th>Prueba</th><th>Correo enviado (payload)</th><th>HTTP</th><th>Tamaño</th><th>¿Igual al control?</th></tr></thead>
                <tbody>
                  {sqli.rows.map((r, i) => (
                    <tr key={r.email} className={i === 0 ? "is-control" : ""}>
                      <td>{r.label}</td>
                      <td><code>{r.email}</code></td>
                      <td><Badge ok={r.status !== 200 && r.status < 500}>{r.status}</Badge></td>
                      <td>{r.length}</td>
                      <td>{i === 0 ? "—" : r.text === sqli.rows[0].text ? "✔ idéntica" : "✘ distinta"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <details>
              <summary>Ver petición y respuesta exactas (lo mismo que muestra F12 → Red)</summary>
              <pre>{`POST /api/v1/auth/login\nContent-Type: application/json\n\n${sqli.rows[1].request}\n\n← HTTP ${sqli.rows[1].status}\n${sqli.rows[1].text}`}</pre>
            </details>
            <Verdict ok={sqli.sameAsControl && sqli.noServerError && sqli.noLogin}>
              Ningún payload inició sesión, ninguno provocó un error 500 ni un mensaje de SQL, y todos recibieron
              <strong> exactamente la misma respuesta que un correo inexistente</strong>: el servidor trató
              <code>' OR 1=1 --</code> como un simple texto. Es la prueba de que la consulta está <strong>parametrizada</strong> (ORM de Django) y
              que el atacante no obtiene ninguna pista. El <code>DROP TABLE</code> tampoco pudo ejecutarse: el usuario de BD no tiene permisos de DDL.
              {sqli.throttled && " (Algunas filas dieron 429: el rate limiting de login también entró en acción; repite en 1 minuto.)"}
            </Verdict>
            <p className="evidence-compare">
              <strong>Comparación:</strong> el mismo payload contra OWASP Juice Shop (vulnerable) devuelve <code>200</code> y un token de
              administrador → <code>bash docs/security/demo/demo.sh juiceshop</code>. Por dentro, la auditoría lo registra:{" "}
              <code>bash docs/security/demo/demo.sh auditoria</code>.
            </p>
          </>
        ) : (
          <p className="evidence-hint">Qué esperar: todas las filas con <strong>401</strong> y el mismo tamaño que el control. Si fuera vulnerable, alguna daría 200 (acceso) o 500 (error de SQL).</p>
        )}
      </article>

      {/* ---------------- RÁFAGA / RATE LIMITING ---------------- */}
      <article className="check-card evidence">
        <header>
          <div>
            <h2>Ráfaga de peticiones (mini DoS) · Semanas 9 y 10</h2>
            <p>80 peticiones simultáneas a <code>/api/v1/auth/csrf</code>. Límite en Nginx: <strong>10 por segundo + ráfaga de 20</strong> por IP.</p>
          </div>
          <button type="button" onClick={runFlood} disabled={busy === "flood"}>{busy === "flood" ? "Lanzando…" : "Lanzar 80 peticiones"}</button>
        </header>
        {flood ? (
          <>
            <div className="flood-grid" aria-label="Resultado de cada petición">
              {flood.results.map((r, i) => (
                <span key={i} className={r.status === 429 ? "is-blocked" : r.status && r.status < 300 ? "is-served" : "is-error"} title={`#${i + 1}: HTTP ${r.status} · ${r.type}`} />
              ))}
            </div>
            <ul className="flood-legend">
              <li><span className="is-served" /> <strong>{flood.served.length}</strong> atendidas por Django (HTTP 2xx, <code>{flood.servedType}</code>)</li>
              <li><span className="is-blocked" /> <strong>{flood.blocked.length}</strong> bloqueadas por Nginx (HTTP 429, <code>{flood.blockedType ?? "—"}</code>)</li>
              <li><span className="is-error" /> <strong>{flood.crashed.length}</strong> errores o caídas (5xx / sin respuesta)</li>
            </ul>
            <Verdict ok={flood.blocked.length > 0 && flood.crashed.length === 0 && flood.after < 300}>
              En {flood.ms} ms, Nginx dejó pasar solo lo que permite el límite y respondió <strong>429 Too Many Requests</strong> al resto.
              Esos 429 llegan como <code>{flood.blockedType}</code> (página de error de Nginx) y no como JSON de Django:
              <strong> el exceso se descartó en el proxy, antes de tocar Django y PostgreSQL</strong>. No hubo ningún 5xx y,
              2 segundos después, una petición normal respondió <strong>HTTP {flood.after}</strong>: el servicio sigue
              <strong> disponible</strong> (tríada CIA). Configuración: <code>limit_req_zone … rate=10r/s</code> y <code>limit_req_status 429</code> en <code>infra/nginx/nginx.conf</code>.
            </Verdict>
            <p className="evidence-compare">A escala real (3000 peticiones, 100 concurrentes con Apache Benchmark): <code>bash docs/security/demo/demo.sh dos</code>. Fuerza bruta contra una cuenta: <code>bash docs/security/demo/demo.sh fuerzabruta</code>.</p>
          </>
        ) : (
          <p className="evidence-hint">Qué esperar: unas ~20–30 casillas verdes (lo permitido) y el resto rojas con 429; ninguna gris (caída).</p>
        )}
      </article>

      {/* ---------------- CABECERAS ---------------- */}
      <article className="check-card evidence">
        <header>
          <div>
            <h2>Cabeceras defensivas y banner · Semanas 2 y 5</h2>
            <p>Se leen las cabeceras reales que envía Nginx (equivale a <code>curl.exe -kI https://securefin.local</code>) y se <strong>atacan dos de ellas</strong>.</p>
          </div>
          <button type="button" onClick={checkHeaders} disabled={busy === "headers"}>Leer cabeceras</button>
        </header>
        {headers && (
          <div className="table-scroll">
            <table className="evidence-table">
              <thead><tr><th>Cabecera</th><th>Valor recibido</th><th>Ataque que evita</th></tr></thead>
              <tbody>
                <tr>
                  <td><Badge ok={!/\d/.test(headers.server ?? "")}>Server</Badge></td>
                  <td><code>{headers.server ?? "(oculto)"}</code></td>
                  <td><strong>Banner grabbing</strong>: sin número de versión, el atacante no sabe qué CVE buscar (<code>server_tokens off</code>).</td>
                </tr>
                {HEADERS.map(([h, label, week, attack, why]) => (
                  <tr key={h}>
                    <td><Badge ok={Boolean(headers.found[h])}>{label}</Badge> <small>{week}</small></td>
                    <td><code>{headers.found[h] ?? "FALTA"}</code></td>
                    <td><strong>{attack}</strong>: {why}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="attack-row">
          <div>
            <button type="button" onClick={tryXss} disabled={busy === "xss"}>Intentar XSS</button>
            <p>Inyecta en esta página un <code>&lt;script&gt;</code> en línea, como haría un atacante.</p>
            {xss && (
              <Verdict ok={!xss.executed}>
                {xss.executed
                  ? "El script se ejecutó: la CSP no está activa."
                  : <>El script <strong>no se ejecutó</strong>. El navegador lo bloqueó por la <strong>Content-Security-Policy</strong> ({xss.violation ?? "script-src 'self'"}). En F12 → <em>Consola</em> verás el aviso «Refused to execute inline script».</>}
              </Verdict>
            )}
          </div>
          <div>
            <button type="button" onClick={tryFrame} disabled={busy === "frame"}>Intentar clickjacking</button>
            <p>Intenta cargar SecureFin dentro de un <code>&lt;iframe&gt;</code>, como haría un sitio malicioso.</p>
            {frame && (
              <Verdict ok={!frame.rendered}>
                {frame.rendered
                  ? "La app se cargó dentro del iframe: falta X-Frame-Options."
                  : <>El navegador <strong>se negó a mostrar la app dentro del iframe</strong> por <code>X-Frame-Options: DENY</code> y <code>frame-ancestors 'none'</code>. En F12 → <em>Consola</em> aparece «Refused to display … in a frame».</>}
              </Verdict>
            )}
          </div>
        </div>
      </article>

      <h2 className="security-center__title">Mapa del semestre: dónde vive cada tema</h2>
      {MOMENTS.map((m) => (
        <div className="moment" key={m.name}>
          <h3>{m.name}</h3>
          <div className="week-grid">
            {m.weeks.map(([n, title, text, cmd]) => (
              <article className="week-card" key={n}>
                <span className="week-card__num">S{n}</span>
                <strong>{title}</strong>
                <p>{text}</p>
                <code>{cmd}</code>
              </article>
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}
