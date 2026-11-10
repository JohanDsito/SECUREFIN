# SecureFin Gateway — Matriz de seguridad del curso

SecureFin Gateway es el módulo de identidad y acceso (IAM) de una fintech de laboratorio: registro,
login con MFA, roles, administración, auditoría y una infraestructura defendida en capas
(Nginx → Django → PostgreSQL en redes aisladas). Esta página relaciona **cada tema del semestre** con
el control que lo aplica, el código donde vive, la **evidencia** generada contra el stack real
(`evidence/`) y la prueba automatizada que lo verifica en cada cambio.

Para la presentación en vivo, ver [DEMO-EN-VIVO.md](DEMO-EN-VIVO.md).

```
Internet ──► [edge_net]  Nginx (TLS 1.2/1.3, cabeceras, rate limit 429, sin root)   ← única zona expuesta (DMZ)
                  │
             [app_net]   Django + DRF (IAM: Argon2id, MFA TOTP, RBAC, CSRF, throttles por IP)   internal
                  │
             [data_net]  PostgreSQL (rol de mínimo privilegio, auditoría append-only)          internal
             [mail_net]  mailer ─► Mailpit (buzón de laboratorio, solo 127.0.0.1:8025 con TLS)   internal
```

## Momento 1 — Fundamentos y seguridad de redes

| Semana | Tema | Control en SecureFin | Dónde | Evidencia | Prueba automatizada |
|---|---|---|---|---|---|
| 1 | Hash con salt | Contraseñas con **Argon2id** (64 MiB, t=3) y salt aleatoria por usuario; nunca SHA-256 "pelado" | `backend/apps/iam/policies/hashers.py` | E2, E7 §4 | `tests/unit/test_password_hasher.py` |
| 1 | Cifrado simétrico (AES) | Secretos TOTP cifrados con **AES-256-GCM**, nonce de 96 bits y AAD ligada al usuario | `backend/apps/iam/crypto/aead.py` | E2, E7 §4 | `tests/unit/test_aead.py` |
| 1 | Asimétrico (RSA/ECC) | Certificado TLS **RSA-3072** firmado por la CA del laboratorio; intercambio **ECDHE** en TLS | `infra/nginx/nginx.conf`, `docs/security/secrets.md` | E2 | — |
| 1 | HMAC / integridad | Tokens de activación y sesiones: solo se guarda **HMAC-SHA-256** con clave dedicada por propósito | `backend/apps/iam/crypto/hmac_verifiers.py` | E7 §4 | `tests/unit/test_hmac_verifiers.py` |
| 2 | HTTP vs HTTPS / MITM | HTTP solo redirige (301); TLS 1.2/1.3; **HSTS**; TLS 1.0/1.1 rechazados | `infra/nginx/nginx.conf` | E1, E2, **E9 (Wireshark)** | `tests/security/test_csrf_cors.py` |
| 2 | Firewall stateful / DPI | Nginx como único punto de entrada; cuerpo máximo 16 KiB; métodos no permitidos → 405 | `infra/nginx/nginx.conf` | E1, E3 | — |
| 3 | VLAN / segmentación LAN | Redes Docker separadas por función (`edge`, `app`, `data`, `mail`); las internas sin salida a Internet | `infra/compose.yaml` | **E7 §1–2** | — |
| 3 | Zero Trust local | Cada petición se reautentica y autoriza en el servidor; la red interna no da confianza | `backend/apps/iam/api/permissions.py` | E7 | `tests/security/test_authz_matrix.py` |
| 4 | AAA — Autenticación | Login con mensaje único (sin enumeración), sesiones de servidor (cookie `__Host-`, HttpOnly, SameSite=Strict), 15 min de inactividad / 8 h máximo | `backend/apps/iam/services/authentication.py`, `backend/apps/iam/sessions/` | E4 | `tests/security/test_login_enumeration.py`, `tests/session_conformance/` |
| 4 | MFA | **TOTP** (RFC 6238) obligatorio para Administrador y Auditor, antirrepetición, 10 códigos de recuperación de un solo uso; reinicio verificado fuera de banda | `backend/apps/iam/services/mfa.py`, `mfa_reset.py` | E6 | `tests/acceptance/test_us3_mfa.py`, `test_us4_admin.py` |
| 4 | AAA — Autorización | RBAC (Cliente/Administrador/Auditor), **denegar por defecto**, control por objeto contra **IDOR/BOLA** (404 idéntico), protección del último administrador | `backend/apps/iam/policies/matrix.py`, `api/permissions.py` | E4 §3 | `tests/security/test_authz_matrix.py`, `test_bola.py` |
| 4 | AAA — Auditoría | Eventos de seguridad **append-only** (triggers + permisos de BD), sin secretos en metadatos | `backend/apps/audit/` | **E7 §3, §5**, E6 | `tests/security/test_db_privileges.py` |
| 4 | RADIUS / TACACS+ | Equivalente en la aplicación: autenticación centralizada en el servicio IAM (un único punto que decide y audita). No se usa RADIUS: no hay equipos de red que lo consuman | `backend/apps/iam/` | — | — |

## Momento 2 — Vulnerabilidad y desarrollo

| Semana | Tema | Control en SecureFin | Dónde | Evidencia | Prueba automatizada |
|---|---|---|---|---|---|
| 5 | Banner grabbing | `server_tokens off` (Nginx sin versión), página de error sin detalles, `TRACE` → 405 | `infra/nginx/nginx.conf` | **E1**, E3 | — |
| 5 | Cabeceras defensivas | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, **CSP** estricta, HSTS, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | `infra/nginx/nginx.conf`, `backend/apps/core/middleware.py` | **E1** | `tests/contract/` (cabeceras) |
| 5 | Hardening del servidor | Nginx **sin root** (uid 101), imagen base parcheada, un solo rango por petición, timeouts cortos | `infra/nginx/Dockerfile`, `nginx.conf` | E3, **E8** | — |
| 6 | Zonas GLOBAL vs DMZ | Solo `edge_net` es pública; backend, BD y correo en redes `internal` | `infra/compose.yaml` | **E7 §2**, E3 | — |
| 6 | Denegar por defecto | Solo se publican 80/443 (y 8025 en loopback); permisos DRF por defecto `IsFullyAuthenticated`; rutas anónimas en lista cerrada | `infra/compose.yaml`, `config/settings/base.py` | E3, E7 | `tests/security/test_route_inventory.py` |
| 6 | NAC | Equivalente: solo entra quien supera TLS + sesión + MFA del rol; un Admin/Auditor sin MFA solo puede darse de alta | `backend/apps/iam/api/permissions.py` | — | `tests/security/test_pre_auth.py` |
| 7 | DevSecOps / CI/CD | GitHub Actions: Semgrep y Bandit (SAST), pip-audit y npm audit (SCA), Trivy (secretos, configuración e imágenes), pruebas en cada push | `.github/workflows/ci.yml`, `.semgrep/` | **E8** | — |
| 7 | Shift-left | Reglas Semgrep propias (vistas sin ORM, sin `localStorage`, E2E sin fugas); dependencias bloqueadas con hashes | `.semgrep/securefin.yml`, `backend/requirements*.txt` | E8 | — |
| 8 | Reconocimiento y escaneo | Nmap `-sV --script vuln`: puertos mínimos, sin versión; falso positivo CVE-2011-3192 analizado y mitigado | — | **E3** | — |
| 8 | Inyección SQL | ORM parametrizado, serializers con lista permitida, rol de BD sin DDL | `backend/apps/iam/api/serializers/` | **E4** | `tests/contract/`, `tests/security/` |

## Momento 3 — Ataque, defensa y auditoría

| Semana | Tema | Control en SecureFin | Dónde | Evidencia | Prueba automatizada |
|---|---|---|---|---|---|
| 9 | DoS / inundación HTTP capa 7 | Ataque con **Apache Benchmark**: el servicio sigue respondiendo a usuarios legítimos | — | **E5** | — |
| 10 | Rate limiting (Nginx) | `limit_req` por IP en tres zonas (auth 10 r/s, api 30 r/s, web 50 r/s), `limit_conn` 20, respuesta **429** | `infra/nginx/nginx.conf` | **E5** | — |
| 10 | Rate limiting (aplicación) | Throttles por IP y ámbito: login 20/min, MFA 10/min, registro 5/h, activación 10/h, reinicio MFA 3/día; 429 + `Retry-After` + evento | `backend/apps/iam/api/throttles.py` | **E6** | `tests/security/test_ip_rate_limits.py` |
| 10 | Server hardening | Ver semana 5 | | E1, E8 | |

## Evidencias (`evidence/`)

| Archivo | Contenido |
|---|---|
| `E1-cabeceras-y-banner.txt` | `curl -I`: cabeceras, banner sin versión, redirección HTTP→HTTPS, `TRACE` 405, protección de cabecera Host |
| `E2-tls-y-criptografia.txt` | Versiones TLS aceptadas/rechazadas, certificado RSA-3072, demo OpenSSL (SHA-256, AES-256, RSA-OAEP, ECDSA P-256) |
| `E3-nmap.txt` | Escaneo de puertos y scripts `vuln`, análisis de hallazgos y verificación de la corrección |
| `E4-inyeccion-sql.txt` | Payloads SQLi contra login, filtros e identificadores; asignación masiva |
| `E5-dos-rate-limiting.txt` | Inundación con `ab` (2000/3000 peticiones): 429 en el proxy y disponibilidad para usuarios legítimos |
| `E6-fuerza-bruta-rate-limit-app.txt` | Diccionario contra login y TOTP: 401 genérico → 429 con `Retry-After` y eventos de auditoría |
| `E7-segmentacion-privilegios-auditoria.txt` | Alcance entre redes, privilegios efectivos en PostgreSQL, almacenamiento de secretos, eventos de auditoría |
| `E8-devsecops.txt` | Semgrep, Bandit, pip-audit, npm audit y Trivy: antes y después de corregir las imágenes |
| `E9-trafico-http-vs-https.txt` | Captura con Wireshark/tshark: credenciales legibles por HTTP, cifradas por HTTPS |

Las evidencias no contienen contraseñas reales, tokens, cookies de sesión ni datos personales: las
cookies se muestran como `<oculto>` y las credenciales usadas son ficticias.

## Riesgos abiertos (honestidad técnica)

| Riesgo | Estado | Plan |
|---|---|---|
| Retrasos progresivos **por cuenta** ante fuerza bruta distribuida (muchas IPs) | Pendiente (US5: T095–T100) | El límite por IP (T101) y el de Nginx ya frenan ataques desde una IP |
| 47 CVE HIGH de Debian 13 en la imagen del backend sin parche publicado | Aceptado y vigilado | Trivy en el CI; valorar imagen base mínima (distroless) |
| Recuperación de contraseña por correo | Pendiente (US7) | Break-glass recupera hoy solo el MFA del último administrador (T141) |
| Recuperación del primer administrador si no activa su cuenta | Pendiente antes de producción | T140 |
| Consulta de eventos por el Auditor desde la API | Pendiente (US6) | Hoy los eventos se consultan en la base de datos |
