# SecureFin Gateway — Fintech simulada con seguridad en capas

Proyecto del curso de Ciberseguridad. SecureFin es un **banco digital ficticio** (registro, login con
MFA, cuentas, transferencias, aprobaciones, administración y auditoría) en el que **cada capa aplica
un tema del semestre**: criptografía, TLS, segmentación por zonas, IAM/AAA, bastionado de Nginx,
DevSecOps, pentesting y defensa contra DoS.

```
Internet ──► [edge_net / DMZ]  Nginx  (TLS 1.2/1.3, cabeceras, rate limit 429, sin root)   ← único expuesto
                   │
              [app_net]        Django + DRF (Argon2id, AES-256-GCM, MFA TOTP, RBAC, CSRF)   interna
                   │
              [data_net]       PostgreSQL (mínimo privilegio, auditoría append-only)       interna
              [mail_net]       mailer ─► Mailpit (buzón de laboratorio)                    interna
              [pentest_net]    OWASP Juice Shop (vulnerable a propósito, solo 127.0.0.1)   aislada
```

| Documento | Para qué |
|---|---|
| **Este README** | Instalar, correr y probar cada tema paso a paso |
| [docs/security/README.md](docs/security/README.md) | Matriz tema → control → código → evidencia → prueba automática |
| [docs/security/DEMO-EN-VIVO.md](docs/security/DEMO-EN-VIVO.md) | Guion de la sustentación (≈ 25 min) |
| [docs/security/DEMO-FINTECH.md](docs/security/DEMO-FINTECH.md) | Demo en vivo de **cada función financiera** (cuentas, transferencias, aprobaciones, roles) |
| [docs/security/packet-tracer.md](docs/security/packet-tracer.md) | VLAN, Wi-Fi WPA2/WPA3, RADIUS/TACACS+, ACL vs firewall stateful, NAC |
| [docs/security/evidence/](docs/security/evidence/) | Salidas guardadas (E1–E9) de cada prueba |

---

## 1. Requisitos (Windows 10/11)

| Herramienta | Para qué | Comprobar |
|---|---|---|
| **Docker Desktop** (WSL 2) | Todo el sistema corre en contenedores | `docker compose version` |
| **Git for Windows** (trae **Git Bash** y **OpenSSL**) | Ejecutar los scripts | `openssl version` |
| Navegador (Chrome/Edge/Firefox) | Usar la app | — |
| App autenticadora (Google/Microsoft Authenticator) | MFA de Administrador | — |
| **Wireshark** (Semana 2) | Captura HTTP vs HTTPS | — |
| **Cisco Packet Tracer** (Semanas 3, 4, 6) | VLAN, Wi-Fi, RADIUS | — |

Nmap, Apache Benchmark (`ab`), Trivy y Juice Shop **no hay que instalarlos**: el script los ejecuta
como contenedores.

> Si en Windows tienes **MySQL (3306)**, **PostgreSQL (5432)**, IIS o XAMPP escuchando en los puertos
> **80/443**, detenlos antes (Servicios de Windows). SecureFin necesita libres 80, 443, 8025 y 3000.

---

## 2. Instalación paso a paso

Todos los comandos son en **Git Bash** (clic derecho en la carpeta → *Open Git Bash here*), desde la
raíz del proyecto (la carpeta que contiene este README).

### Paso 1 — Abrir Docker Desktop

Espera a que diga **Engine running** (ícono de la ballena en verde).

### Paso 2 — Nombre del servidor (`securefin.local`)

Django solo acepta peticiones dirigidas a `securefin.local` (protección de cabecera Host). Abre
**PowerShell como Administrador** y ejecuta una sola vez:

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "127.0.0.1 securefin.local"
```

> **¿Equipo de laboratorio sin permisos de administrador?** Abre Chrome así (cierra antes todas sus
> ventanas): `"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-resolver-rules="MAP securefin.local 127.0.0.1"`.
> Los scripts de la demo detectan solos que falta la entrada y usan `curl --resolve`.

### Paso 3 — Generar secretos y levantar todo

```bash
bash scripts/setup.sh
```

El script:

1. Genera en `secrets/` (ignorado por git) las claves de 256 bits, las contraseñas de la base de
   datos, una **CA RSA-3072** y el certificado TLS de `securefin.local`.
2. **Imprime la contraseña del buzón Mailpit** (usuario `labmail`). **Anótala**: no se guarda en
   claro en ningún sitio.
3. Levanta la base de datos → aplica migraciones → levanta backend, mailer, Mailpit y Nginx.

La primera vez tarda **5–10 minutos** (descarga y compila imágenes). Al final verás 5 contenedores
`(healthy)`. Para comprobarlo después: `bash docs/security/demo/demo.sh estado`.

### Paso 4 — Abrir la aplicación

Entra en **https://securefin.local**. El navegador avisará de que el certificado no es de confianza
(lo firmó la CA del laboratorio): *Avanzado → Continuar a securefin.local*.

> Opcional, para quitar el aviso: importa `secrets/lab_ca.pem` en *Administrar certificados →
> Entidades de certificación raíz de confianza* y quítalo al terminar el curso.

### Paso 5 — Crear las cuentas de la demo

**Cliente** (desde el navegador): *Abrir cuenta* → correo `cliente@lab.securefin.local`, nombre,
contraseña larga (15+ caracteres, p. ej. `una frase larga de prueba 2026`). Al entrar recibes una
cuenta de ahorros con **$5.000.000 COP ficticios**.

**Administrador** (solo por consola, nunca desde la web):

```bash
docker compose -f infra/compose.yaml exec backend \
  python manage.py iam_bootstrap_admin --email admin@lab.securefin.local --name "Admin Lab"
```

1. Abre el buzón **https://127.0.0.1:8025** (usuario `labmail` + la contraseña del Paso 3).
2. Abre el correo *Activa tu cuenta* → enlace → fija una contraseña larga.
3. Inicia sesión en https://securefin.local/login → te **obliga a configurar MFA**: escanea el QR
   con la app autenticadora y **guarda los 10 códigos de recuperación**.
4. Desde *Administración → Usuarios* crea un **Auditor** (también recibirá correo y tendrá MFA
   obligatorio).

### Comandos útiles

| Acción | Comando |
|---|---|
| Ver estado | `bash docs/security/demo/demo.sh estado` |
| Detener (conserva datos) | `bash scripts/setup.sh parar` |
| Volver a arrancar | `bash scripts/setup.sh arrancar` |
| Levantar Juice Shop (Semana 8) | `bash scripts/setup.sh pentest` |
| Ver logs | `docker compose -f infra/compose.yaml logs -f nginx backend` |
| **Empezar de cero** (borra BD y secretos) | `bash scripts/setup.sh reset` |

---

## 3. Qué hay en la aplicación (parte visual)

| Pantalla | Ruta | Tema que evidencia |
|---|---|---|
| Portada de la fintech | `/` | — |
| **Centro de seguridad** (pruebas en vivo con un clic) | `/seguridad` | S2, S4, S5, S8, S9, S10 |
| Registro / Login / MFA | `/register`, `/login` | S1 (Argon2id), S4 (AAA, MFA) |
| Panel financiero, cuentas, transferencias, movimientos | `/finance` | S4 (control por objeto, anti-IDOR) |
| Perfil y sesiones activas | `/profile`, `/sessions` | S4 (MFA, revocación de sesiones) |
| Usuarios, reinicios de MFA, aprobaciones (Admin) | `/admin/...` | S4 (RBAC, denegar por defecto) |

El **Centro de seguridad** tiene botones que, desde el navegador, comprueban HTTPS, que la cookie de
sesión es `HttpOnly`, las cabeceras defensivas y el banner, lanzan `' OR 1=1 --` contra el login y
disparan una ráfaga de 80 peticiones para ver los **429**. Es ideal para abrir la sustentación.

---

## 4. Cómo ejecutar y evidenciar cada tema

Formato: **comando** → **qué se ve** → **dónde está el control** → **evidencia guardada**.
Todos los `demo.sh` se ejecutan en Git Bash con el stack levantado.

### Momento 1 — Fundamentos y seguridad de redes

**Semana 1 · Criptografía (AES, RSA/ECC, SHA-256, hash con salt)**

```bash
bash docs/security/demo/demo.sh cripto
```

- Se ve: el mismo texto da el **mismo SHA-256** (por eso hace falta salt); con salt aleatoria cambia;
  AES-256 cifra/descifra; RSA-3072 cifra con la pública y descifra con la privada; ECC P-256 firma y
  verifica (`Verified OK`); y el formato real de las contraseñas en la BD:
  `argon2$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`.
- Código: `backend/apps/iam/policies/hashers.py` (Argon2id), `backend/apps/iam/crypto/aead.py`
  (AES-256-GCM de los secretos TOTP), `backend/apps/iam/crypto/hmac_verifiers.py` (HMAC-SHA-256).
- Evidencia: `E2-tls-y-criptografia.txt`, `E7` §4.

**Semana 2 · Redes, OSI, HTTP vs HTTPS, MITM, DPI, firewalls**

1. **Wireshark** → *Capture → Options* → marca **Enable promiscuous mode** → interfaz
   **Adapter for loopback traffic capture** → Start. Filtro de visualización: `tcp.port == 80 || tcp.port == 443`.
2. En Git Bash:

   ```bash
   curl -s -o /dev/null -X POST http://127.0.0.1/api/v1/auth/login -H "Content-Type: application/json" \
     --data '{"email":"demo@lab.securefin.local","password":"ClaveFicticia-Clase"}'
   curl -sk -o /dev/null -X POST https://securefin.local/api/v1/auth/login -H "Content-Type: application/json" \
     --data '{"email":"demo@lab.securefin.local","password":"ClaveFicticia-Clase"}'
   bash docs/security/demo/demo.sh tls
   ```

3. Qué mostrar:
   - **Capas OSI** en el panel de detalle de un paquete: *Ethernet/Null* (L2), *IPv4* (L3), *TCP*
     (L4), *HTTP* (L7).
   - **DPI**: filtro `http contains "password"` → clic derecho → *Follow → HTTP Stream*: la contraseña
     **en claro** por el puerto 80 (lo que vería un atacante MITM). *Statistics → Protocol Hierarchy*.
   - Por 443, filtro `tls.handshake.type == 1`: solo el *Client Hello* (SNI) y *Application Data* cifrado.
   - `tls`: TLS 1.3/1.2 aceptados, **TLS 1.1 rechazado**, certificado RSA-3072.
   - La respuesta de Nginx al puerto 80 es **301 → HTTPS** y **HSTS** evita esa primera petición en claro.
- **Firewall stateless vs stateful**: ver [packet-tracer.md §6](docs/security/packet-tracer.md).
- Evidencia: `E9-trafico-http-vs-https.txt`, `E1`, `E2`.

**Semana 3 · LAN, VLAN, Wi-Fi WPA2/WPA3, Zero Trust local**

```bash
bash docs/security/demo/demo.sh red
```

- Se ve: 4 redes; solo `edge_net` es pública; desde la DMZ la BD y el backend están **BLOQUEADOS**;
  el backend **no tiene salida a Internet**.
- VLAN 802.1Q reales y Wi-Fi **WPA2-Enterprise/WPA3**: [packet-tracer.md §2 y §5](docs/security/packet-tracer.md).
- Código: `infra/compose.yaml` (`internal: true`). Evidencia: `E7` §1–2.

**Semana 4 · IAM: AAA, MFA, RADIUS/TACACS+, Zero Trust**

En el navegador (ver [DEMO-EN-VIVO.md §5](docs/security/DEMO-EN-VIVO.md)):
1. **Autenticación + MFA**: login del Administrador → pide el código TOTP.
2. **Autorización**: como Cliente abre `https://securefin.local/admin/users` → "No tienes permiso" (403).
3. **Revocación**: el Admin desactiva al Cliente → su sesión muere al recargar.
4. **Auditoría**: `bash docs/security/demo/demo.sh auditoria` y `bash docs/security/demo/demo.sh privilegios`
   (la app puede `INSERT` en auditoría pero **no** `UPDATE/DELETE/TRUNCATE`).
- **RADIUS/TACACS+**: [packet-tracer.md §4](docs/security/packet-tracer.md) (router que autentica
  por SSH contra un servidor AAA central).
- Código: `backend/apps/iam/policies/matrix.py`, `api/permissions.py`, `services/mfa.py`, `backend/apps/audit/`.

### Momento 2 — Vulnerabilidad y desarrollo

**Semana 5 · Bastionado web (banner grabbing, cabeceras)**

```bash
bash docs/security/demo/demo.sh cabeceras
curl.exe -kI https://securefin.local          # mismo resultado desde PowerShell
```

- Se ve: `Server: nginx` **sin versión** (`server_tokens off`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, CSP, HSTS, `Referrer-Policy`; HTTP → 301; `TRACE` → 405.
- Código: `infra/nginx/nginx.conf`, `infra/nginx/Dockerfile` (`USER nginx`, sin root).
- Evidencia: `E1-cabeceras-y-banner.txt`. En la app: *Centro de seguridad → Comprobar*.

**Semana 6 · NAC y cortafuegos (GLOBAL vs DMZ, DENY por defecto)**

```bash
bash docs/security/demo/demo.sh red
bash docs/security/demo/demo.sh nmap
```

- Se ve: solo 80/443 publicados (8025 solo en loopback); 8000 (backend) y 1025 (correo) cerrados.
- Denegar por defecto también en la app: permiso DRF por defecto `IsFullyAuthenticated`
  (`backend/config/settings/base.py`) y rutas anónimas en lista cerrada
  (`tests/security/test_route_inventory.py`).
- NAC y firewall de zonas con equipos: [packet-tracer.md §6–7](docs/security/packet-tracer.md).

**Semana 7 · DevSecOps (Shift-Left, CI/CD, SAST/SCA, Trivy)**

```bash
bash docs/security/demo/demo.sh trivy
```

- Pipeline: `.github/workflows/ci.yml` → Semgrep + Bandit (SAST), pip-audit + npm audit (SCA),
  Trivy (secretos, configuración e imágenes de backend y Nginx), pruebas unitarias, de integración y E2E,
  y una **prueba de humo** de los controles del stack ya levantado (`bash scripts/smoke-stack.sh`,
  también ejecutable en local: cabeceras, banner, TLS, 301, TRACE, SQLi y 429).
- Para verlo correr: sube el repo a GitHub y abre la pestaña **Actions** (cada `push` a `main` o PR
  lo ejecuta). Captura los trabajos en verde.
- Evidencia: `E8-devsecops.txt` (73 CVE en Nginx → 0 tras actualizar y parchear).

**Semana 8 · Pentesting (reconocimiento, escaneo, vulnerabilidades, SQLi)**

```bash
bash docs/security/demo/demo.sh nmap        # Reconocimiento + escaneo + nmap --script vuln
bash docs/security/demo/demo.sh sqli        # payloads SQLi contra SecureFin → 401 genérico
bash scripts/setup.sh pentest               # levanta OWASP Juice Shop (espera ~30 s)
bash docs/security/demo/demo.sh juiceshop   # la MISMA inyección: Juice Shop cae, SecureFin no
```

- Se ve: en **Juice Shop** `' OR 1=1 --` devuelve un **token de administrador** (200); en
  **SecureFin** el mismo payload da **401**. También puedes escribirlo en el formulario de login de
  http://127.0.0.1:3000 y en el de https://securefin.local.
- Por qué: ORM con consultas **parametrizadas**, serializers con lista permitida (`"role":"admin"` → 400)
  y usuario de BD **sin DDL** (un `DROP TABLE` no puede ejecutarse aunque se inyectara).
- Evidencia: `E3-nmap.txt` (incluye el hallazgo CVE-2011-3192 y su mitigación `max_ranges 1`), `E4-inyeccion-sql.txt`.

### Momento 3 — Ataque, defensa y auditoría

**Semana 9 · DoS / inundación HTTP en capa 7**

```bash
bash docs/security/demo/demo.sh dos
```

- Apache Benchmark lanza **3000 peticiones con 100 concurrentes** contra Nginx. Mientras corre,
  recarga https://securefin.local: **sigue respondiendo** (Disponibilidad de la tríada CIA).

**Semana 10 · Mitigación: rate limiting (429/503) y hardening**

- En la salida de `dos`: ~2800 de 3000 respuestas son **`429 Too Many Requests`**, descartadas en el
  proxy antes de llegar a Django/PostgreSQL.
- Se eligió **429** y no 503 a propósito: 503 significa "servidor caído"; 429 dice "eres tú, frena"
  y permite distinguir la limitación de una caída real en los logs. (Cambiar a 503 es una línea:
  `limit_req_status 503;` en `nginx.conf`.)
- Segunda capa, en la aplicación:

  ```bash
  bash docs/security/demo/demo.sh fuerzabruta   # espera 1 min tras la demo de SQLi
  ```

  Intentos 1–20 → 401; desde el 21 → **429 + `Retry-After`**; la auditoría muestra que solo **5**
  contraseñas se evaluaron (retrasos progresivos por cuenta 30 s → 900 s).
- Código: `infra/nginx/nginx.conf` (`limit_req_zone`, `limit_conn`), `backend/apps/iam/api/throttles.py`,
  `backend/apps/iam/services/throttling.py`. Evidencia: `E5`, `E6`.

---

## 5. Pruebas automatizadas

El proyecto tiene **383 pruebas** en `backend/tests/` (unitarias, de integración, de contrato, de
seguridad —BOLA/IDOR, CSRF, enumeración, fuerza bruta, matriz de autorización— y del stack) más E2E
con Playwright en `frontend/tests/e2e/`. Se ejecutan **en GitHub Actions** en cada push (pestaña
*Actions*): es la evidencia de la Semana 7.

La imagen del backend no trae `pip` a propósito (hardening: un atacante no podría instalar
herramientas), así que las pruebas no se corren dentro del contenedor. Para las unitarias en local
necesitas **Python 3.13**:

```bash
cd backend && python -m venv .venv && source .venv/Scripts/activate
pip install --require-hashes -r requirements.txt && pip install -r requirements-dev.txt
pytest -m unit
```

---

## 6. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `db-1 exited (127)` / `cannot execute: required file not found` | Git convirtió los `.sh` a CRLF (Windows) | Corregido con `.gitattributes` para clones nuevos. En una copia antigua: `sed -i 's/\r$//' infra/postgres/init/01-roles.sh scripts/*.sh docs/security/demo/demo.sh`, luego `docker compose -f infra/compose.yaml down -v` y `bash scripts/setup.sh arrancar` |
| `Bind for 0.0.0.0:80 failed` | Otro programa usa el puerto 80/443 | Detén IIS/XAMPP/Apache/Skype |
| La API responde **400 Bad Request** | Entraste por `https://127.0.0.1` | Usa **https://securefin.local** |
| `securefin.local` no carga | Falta la línea en `hosts` | Paso 2 |
| Login devuelve 429 antes de tiempo | Muchos intentos en el último minuto desde tu IP | Espera 1 minuto |
| No llega el correo de activación | El mailer está arrancando | `bash docs/security/demo/demo.sh estado` y espera |
| Olvidé la contraseña de Mailpit | No se guarda en claro | `bash scripts/setup.sh mailpit` (genera otra y reinicia Nginx y Mailpit) |
