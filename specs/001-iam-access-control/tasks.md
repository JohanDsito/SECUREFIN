---

description: "Lista de tareas de implementación de la Feature 001 — IAM"
---

# Tasks: Sistema de Identidad y Control de Acceso (IAM)

**Input**: Documentos de diseño en `specs/001-iam-access-control/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/iam-api.md,
quickstart.md y la constitución v1.2.0.

**Tests**: **obligatorios**. FR-050 exige pruebas positivas y negativas reproducibles por requisito,
y el Principio V de la constitución exige Pytest con casos negativos. En cada fase, las pruebas se
escriben **primero** y deben **fallar** antes de implementar.

**Organization**: tareas agrupadas por historia de usuario (US1–US7 de spec.md) para implementarlas
y probarlas de forma independiente.

**Revisión 3** (corrección de `/speckit-analyze`): se conservan T001–T128. Hay tareas nuevas, cada
una en su fase: T129 (supresiones, Setup), T130 (privacidad, Polish), T131 (tiempos del login,
US1), T132 (límites por IP, US5), T133 (E2E de campos de contraseña, US1) y T134 (emisión de la
cookie y `session_expired`, Foundational). Se modificaron T004, T005, T006, T011, T012, T014, T015,
T016, T020, T027, T029, T033, T034, T035, T050, T051, T086, T087, T089, T098, T120, T121, T122 y T125.

**Revisión 4** (corrección final del análisis de la revisión 3): se conservan T001–T134 y se añaden
T135 (E2E de activación, US4), T136 (E2E de recuperación, US7), T137 (límite por IP `recovery`, US7)
y T138 (pruebas de la purga controlada, Polish). Se modificaron:

| Hallazgo | Tareas modificadas |
|---|---|
| I1 | T133 (solo formularios de US1) |
| I2 | T132 (sin `recovery`) y T101 |
| I3 | T020, T033, T034, T077 y T134 (SC18) |
| U1 | T056, T093 y T115 |
| G1 | T099 y T117 |
| D1 | T022 (sin la comprobación de credenciales) y T120 |

Cada historia supera su checkpoint sin depender de historias posteriores.

**Revisión 5** (revisión final de seguridad de Playwright, Mailpit y sesiones): se conservan
T001–T138 y se añade T139 (*fixture* autenticado de la API de Mailpit, US4). Se modificaron:

| Hallazgo | Tareas modificadas |
|---|---|
| U1 | T006, T013, T014, T122, T135 y T136 |
| U2 | T014, T122, T135, T136 y T139 |
| I1 | T020, T033, T034 y T134 (SC19) |
| U3 | T034, T035, T069, T076 y T134 (SC20) |
| U4 | T115 y T136 |
| TLS en el proxy de Mailpit (detectado al corregir U2) | T010, T012 y T120 |

## Format: `[ID] [P?] [Story] Description`

- **[P]**: paralelizable (archivos distintos, sin dependencias pendientes).
- **[Story]**: historia a la que pertenece (US1…US7).
- Las rutas siguen la estructura de `plan.md`: `backend/`, `frontend/`, `infra/`, `docs/security/`,
  `.semgrep/` y `.github/`.

## Path Conventions

- Backend: `backend/config/`, `backend/apps/{core,iam,audit}/`, `backend/tests/{unit,integration,session_conformance,security,contract,acceptance}/`
- Frontend: `frontend/src/{api,lib,pages,components}/`
- Infraestructura: `infra/{nginx,postgres}/`, `infra/compose.yaml`
- Documentación de seguridad (FR-049): `docs/security/`

## Reglas transversales (aplican a todas las tareas)

- Ningún secreto (contraseña, token, código, secreto TOTP o valor de cookie de sesión) se escribe
  en la base de datos en claro, en logs, en eventos ni en el outbox (Principio III, R2, R7, R9).
- Toda operación administrativa escribe su evento con `audit.services.record_event` **dentro de la
  misma `transaction.atomic`** (FR-044).
- Toda vista anónima que cambie estado lleva `csrf_protect`; no se usa `csrf_exempt` ni CORS (R3).
- Solo identidades ficticias del dominio `@lab.securefin.local`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: inicializar el repositorio, las dependencias bloqueadas, los contenedores y la CI.

- [X] T001 Crear la estructura de directorios de `plan.md` → Project Structure: `backend/config/settings/`, `backend/apps/core/`, `backend/apps/iam/{models,sessions,services,crypto,policies,api,management/commands}/`, `backend/apps/audit/`, `backend/tests/{unit,integration,session_conformance,security,contract,acceptance}/`, `frontend/`, `infra/nginx/`, `infra/postgres/init/`, `docs/security/evidence/`, `.semgrep/` y `.github/workflows/`, con un `__init__.py` en cada paquete Python
- [X] T002 [P] Ampliar `.gitignore` con `secrets/`, `*.pem`, `*.key`, `.env`, `node_modules/`, `frontend/dist/`, `__pycache__/`, `.coverage` y `htmlcov/`
- [X] T003 Crear `backend/requirements.in` y `backend/requirements-dev.in`:
  - **`requirements.in`**: `Django>=5.2.17,<5.3` (usar la última 5.2.x publicada); `djangorestframework` (por ahora la última 3.16.x; la 3.18.1 se evalúa en T126); `argon2-cffi`, `cryptography`, `pyotp`, `segno`, `psycopg[binary]>=3` y `gunicorn`.
  - **`requirements-dev.in`**: `pytest`, `pytest-django`, `pytest-cov`, `pip-tools`, `bandit` y `pip-audit`.
  - Compilar con `pip-compile --generate-hashes` sobre Python 3.13 en `backend/requirements.txt` y `backend/requirements-dev.txt` (R17).
- [X] T004 Crear la configuración de Django en `backend/config/settings/base.py`, `lab.py` y `test.py`, más `backend/config/urls.py` y `backend/config/wsgi.py` (R2, R3, R4, R12, R13, R14):
  - **Aplicaciones**: `INSTALLED_APPS` **sin** `django.contrib.admin` **ni** `django.contrib.sessions`.
  - **Usuario**: `AUTH_USER_MODEL = "iam.User"`.
  - **Sesión**: `SESSION_ENGINE = "apps.iam.sessions.store"`, `SESSION_COOKIE_NAME = "__Host-sf_session"`, `SESSION_COOKIE_SECURE = SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Strict"`, **`SESSION_SAVE_EVERY_REQUEST = False`**, `SESSION_EXPIRE_AT_BROWSER_CLOSE = True` (cookie sin `Expires`) y `SESSION_COOKIE_AGE = 28800` (solo como tope absoluto de 8 h). La inactividad de 15 min la controla el motor con `last_activity_at` (R2, R13; corrección C2). La cookie solo se emite al crear o rotar la sesión.
  - **CSRF**: `CSRF_COOKIE_NAME = "__Host-sf_csrftoken"`, `CSRF_COOKIE_SECURE = True`, `CSRF_COOKIE_SAMESITE = "Strict"`, `CSRF_USE_SESSIONS = False` y `CSRF_TRUSTED_ORIGINS = ["https://securefin.local"]`.
  - **Proxy**: `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` y `ALLOWED_HOSTS = ["securefin.local"]`.
  - **Contraseñas**: `PASSWORD_HASHERS = ["apps.iam.policies.hashers.SecureFinArgon2Hasher"]` (único).
  - **Caché**: `CACHES` con `DatabaseCache`.
  - **Base de datos** (corrección U1): `DATABASES` con `OPTIONS: {"options": "-c search_path=securefin"}`; el usuario y la contraseña se leen de `DB_USER` y `DB_PASSWORD_FILE` del entorno de **cada servicio**. En ejecución (`backend`, `mailer`), siempre `securefin_app` y `/run/secrets/db_app_password`; solo el servicio `migrate` recibe `securefin_owner` y `/run/secrets/db_owner_password`. Variable `SECUREFIN_PROCESS_ROLE` (`runtime` \| `migrate`) que valida T027.
  - **Correo**: `EMAIL_BACKEND` SMTP hacia `mailpit:1025` sin TLS y `EMAIL_TIMEOUT = 3`; en `test.py`, `locmem`.
  - **Entorno**: `DEBUG = False` en `lab.py`.
- [X] T005 Configurar Pytest en `backend/pytest.ini` y `backend/tests/conftest.py`:
  - Marcadores `unit` (sin base de datos), `integration`, `session_conformance`, `security`, `contract`, `acceptance` y `stack` (necesita el stack de Compose); `--strict-markers`; `DJANGO_SETTINGS_MODULE = config.settings.test`.
  - Para las pruebas `stack`, un *hook* en `conftest.py` hace **fallar** (nunca `skip`) si el stack no responde (corrección U2).
  - Fixtures: cliente API con ayuda CSRF (obtiene `/api/v1/auth/csrf` y envía `X-CSRFToken` + `Origin: https://securefin.local`), funciones para crear usuarios ficticios por rol y fixture de reloj que parchea `apps.core.clock.now`.
- [X] T006 [P] Inicializar el frontend en `frontend/` (`package.json`, `package-lock.json`, `vite.config.js`, `index.html`, `src/main.jsx`, `src/App.jsx`):
  - Vite + React 19 + react-router, sin otras dependencias de ejecución.
  - `@playwright/test` **solo en `devDependencies`** (justificado en R17, corrección G3), con `frontend/tests/e2e/` y `frontend/playwright.config.js` (`baseURL https://securefin.local`, CA de laboratorio aceptada). No forma parte del bundle ni de la imagen de Nginx.
  - **Protección de tokens** en `playwright.config.js` (corrección U1): `use: { trace: "off", video: "off", screenshot: "off" }`, `reporter: [["list"]]` (sin informe HTML ni JSON) y un `outputDir` temporal fuera del repositorio que se borra en `globalTeardown`. Una regla de Semgrep en `.semgrep/securefin.yml` (T013) prohíbe `console.log` en `frontend/tests/e2e/`.
  - En desarrollo, proxy de `/api` en `vite.config.js` para conservar el mismo origen (R3).
- [X] T007 [P] Crear `backend/Dockerfile` multietapa:
  - Base `python:3.13-slim@sha256:<digest>` y usuario no root.
  - `pip install --require-hashes --no-deps -r requirements.txt`.
  - Arranque con `gunicorn config.wsgi --workers 4 --threads 1` (R4, R17).
- [X] T008 [P] Crear `infra/nginx/Dockerfile` multietapa: compila el frontend con `node:22-alpine@sha256:<digest>` (`npm ci && npm run build`) y copia `dist/` a `nginx:1.28-alpine@sha256:<digest>`
- [X] T009 [P] Crear `infra/postgres/init/01-roles.sh`, que lee las contraseñas de `/run/secrets` (R14):
  - Roles `securefin_owner` (LOGIN) y `securefin_app` (LOGIN).
  - `CREATE SCHEMA securefin AUTHORIZATION securefin_owner` y `REVOKE ALL ON SCHEMA public FROM PUBLIC`.
  - `GRANT USAGE ON SCHEMA securefin TO securefin_app`, sin CREATE.
  - `ALTER DEFAULT PRIVILEGES FOR ROLE securefin_owner IN SCHEMA securefin GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO securefin_app`.
- [X] T010 Crear `infra/nginx/nginx.conf` (R3, R7, R10, R12):
  - **TLS**: `server` en 443 con TLS 1.2/1.3 y certificado de la CA de laboratorio; `server` en 80 que redirige a 443.
  - **Cabeceras**: `Strict-Transport-Security`, la CSP literal de `contracts/iam-api.md` §6, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` y `Cache-Control: no-store` para `index.html`.
  - **SPA**: `try_files` hacia `index.html`.
  - **API**: `location /api/` → `backend:8000` con `X-Forwarded-For` y `X-Forwarded-Proto`; `client_max_body_size 16k`; `limit_req` de 10 r/s con ráfaga de 20 en `/api/v1/auth/`.
  - **Logs**: `log_format` sin cuerpos, cookies ni `Authorization`.
  - **Mailpit**: segundo `server` en `listen 8025 ssl` (TLS 1.2/1.3, certificado de laboratorio con SAN `IP:127.0.0.1`) con `auth_basic` → `proxy_pass http://mailpit:8025` (interfaz y API `/api/v1/`). Reenvía la cabecera `Authorization` para que Mailpit valide la **misma** credencial Basic, y **no** acepta HTTP plano en 8025 (Principio III; R10).
- [X] T011 Crear `infra/compose.yaml` (R10, R14, `plan.md` → Despliegue):
  - **Servicios**: `nginx`, `backend`, `mailer` (comando `iam_deliver_outbox`), `migrate` (de un solo uso: `migrate` + `createcachetable`), `db` (`postgres:17@sha256:<digest>`) y `mailpit` (`axllent/mailpit:vX.Y.Z@sha256:<digest>`).
  - **Redes**: `edge_net` (bridge); `app_net`, `data_net` y `mail_net` con `internal: true`.
  - **Miembros**: nginx → edge, app, mail; backend → app, data; mailer → data, mail; migrate → data; db → data; mailpit → mail.
  - **Puertos**: solo nginx publica `443`, `80` y `127.0.0.1:8025`.
  - **Secretos y credenciales por servicio** (U1): `db_owner_password` y `DB_USER=securefin_owner` **solo** en `migrate` (`SECUREFIN_PROCESS_ROLE=migrate`); `backend` y `mailer` con `DB_USER=securefin_app`, `db_app_password` y `SECUREFIN_PROCESS_ROLE=runtime`. Las cinco claves (`django_secret_key`, `session_hmac_key_v1`, `token_hmac_key_v1`, `throttle_hmac_key_v1` y `totp_key_v1`) solo en `backend` y `mailer`.
  - **Healthchecks** (U2):
    - `db`: `pg_isready`;
    - `backend`: comprobación TCP del puerto 8000 con `python -c`, sin endpoint nuevo;
    - `mailer`: proceso vivo;
    - `mailpit`: `/readyz`;
    - `nginx`: `curl -kf https://localhost/`.

    Con dependencias `depends_on: condition: service_healthy`.
  - **Mailpit**: `MP_MAX_MESSAGES=200`, `MP_MAX_AGE=24h`, `MP_UI_AUTH_FILE` y `MP_BLOCK_REMOTE_CSS_AND_FONTS=true`, y **ninguna** variable `MP_SMTP_RELAY_*`.
- [X] T012 [P] Crear `.env.example` y `docs/security/secrets.md`: generación con `openssl rand -base64 32` de las cinco claves (`DJANGO_SECRET_KEY`, `SESSION_HMAC_KEYS`, `TOKEN_HMAC_KEYS`, `THROTTLE_HMAC_KEYS` y `TOTP_ENCRYPTION_KEYS`, una por propósito y todas distintas) y de las contraseñas de los roles (quickstart §2), CA y certificado TLS de laboratorio con OpenSSL (SAN `DNS:securefin.local` e `IP:127.0.0.1`, este último para el proxy de Mailpit), y credenciales de autenticación básica de Nginx y Mailpit, sin valores reales
- [X] T013 [P] Crear las reglas de Semgrep propias en `.semgrep/securefin.yml`: prohibir `csrf_exempt` y la importación de `corsheaders`; prohibir el acceso a `.session_key` fuera de `backend/apps/iam/sessions/`; alertar de `objects.` en `backend/apps/iam/api/views/`; prohibir `localStorage` y `sessionStorage` en `frontend/src/`; prohibir `console.log`, `console.info` y `page.screenshot` en `frontend/tests/e2e/` (U1)
- [X] T014 Crear el pipeline de CI en `.github/workflows/ci.yml` con **cuatro trabajos separados** (R16; correcciones U2 y U4):
  - **`static`**: `semgrep ci` (`p/django`, `p/python`, `p/react`, `p/secrets` y `.semgrep/`), `bandit -r backend/ -ll`, `pip-audit -r backend/requirements.txt --require-hashes`, `npm ci && npm audit --omit=dev` y `trivy fs --scanners misconfig,secret .`.
  - **`unit`**: `pytest -m unit` (sin base de datos).
  - **`integration`**: servicio `postgres:17` inicializado con `infra/postgres/init/01-roles.sh`; `pytest -m "integration or session_conformance or security or contract or acceptance" -m "not stack" --cov`.
  - **`stack`**:
    1. Genera **secretos efímeros** en `secrets/` del runner con `openssl rand -base64 32`: las cinco claves, las contraseñas de los roles y las credenciales básicas de Nginx y Mailpit, más un certificado TLS efímero con OpenSSL. **Nunca** secretos reales, de GitHub ni versionados; se borran al terminar.
    2. `docker compose -f infra/compose.yaml up -d --build --wait` (espera los healthchecks de T011).
    3. `docker compose run --rm migrate`.
    4. `pytest -m stack` y `npx --prefix frontend playwright test`, con `MAILPIT_API_USER` y `MAILPIT_API_PASSWORD` exportadas como variables efímeras del paso (corrección U2). La credencial también se escribe en el `htpasswd` de Nginx y en el `MP_UI_AUTH_FILE` efímeros.
    5. `trivy image` sobre las imágenes construidas.
    6. **Limpieza siempre**, también si hay fallos (`if: always()`): borrar todos los mensajes de Mailpit con `DELETE /api/v1/messages`, después `docker compose down -v` y borrar `secrets/`, `frontend/test-results/` y `outputDir`.
    - **Sin artefactos sensibles** (corrección U1): el trabajo **no** usa `actions/upload-artifact` para `test-results/`, `playwright-report/`, trazas, vídeos ni capturas. Solo se conserva como evidencia el resumen textual sanitizado del reporter `list` (nombres de prueba y resultado). Los pasos no imprimen URLs completas, tokens ni cuerpos de correo.
  - **Sin omisiones silenciosas**: cada paso de pytest falla con 0 pruebas recogidas (código 5); `--strict-markers`; el resumen debe mostrar 0 `skipped` en `stack` y `e2e`.
  - Todo el pipeline falla con severidad alta o crítica; las supresiones siguen T129.
- [X] T129 [P] Crear `.github/pull_request_template.md` y `docs/security/suppressions.md` (Principio V; corrección C3):
  - Toda supresión de un hallazgo (Semgrep, Bandit, pip-audit, npm audit o Trivy) debe registrar **justificación**, **alcance** (herramienta, regla e identificador, archivo o línea o paquete; nunca reglas desactivadas globalmente), **responsable** y **fecha de revisión**, y aprobarse explícitamente en el PR.
  - Se distingue un *falso positivo* (supresión específica en el código o en el archivo de la herramienta, con comentario que remite al PR) de una *excepción por riesgo real* (registro adicional en `plan.md` → Complexity Tracking).
  - La plantilla de PR incluye la casilla de supresiones con esos campos y la verificación de que no se introducen secretos.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: claves, criptografía, modelo de usuario, **motor de sesión**, auditoría, marco de
autorización, tokens y outbox. Todo lo que necesitan las historias.

**⚠️ CRITICAL**: ninguna historia puede empezar antes de terminar esta fase. El modelo `User` debe
existir antes de la primera migración.

### Pruebas fundamentales (escribir primero; deben fallar)

- [X] T015 [P] Prueba unitaria TS-U07 en `backend/tests/unit/test_keys.py`:
  - El arranque falla si falta alguna de `DJANGO_SECRET_KEY`, `SESSION_HMAC_KEYS`, `TOKEN_HMAC_KEYS`, **`THROTTLE_HMAC_KEYS`** o `TOTP_ENCRYPTION_KEYS`.
  - También falla si alguna versión mide menos de 32 bytes o si **dos claves cualesquiera coinciden**, en particular `THROTTLE_HMAC_KEYS` frente a `TOKEN_HMAC_KEYS` o `SESSION_HMAC_KEYS` (C1).
  - Un proceso con `SECUREFIN_PROCESS_ROLE=runtime` conectado como `securefin_owner` no arranca (U1).
  - El error no revela valores.
- [X] T016 [P] Prueba unitaria TS-U06 en `backend/tests/unit/test_hmac_verifiers.py`:
  - El verificador de sesión tiene el formato `^v\d{1,5}\$[0-9a-f]{64}$`.
  - Hay separación de dominio: `"securefin:session:"`, `"<purpose>:"` y `"throttle:acct:"` producen verificadores distintos para la misma entrada.
  - **Separación de claves** (C1): `session_verifier` solo usa `SESSION_HMAC_KEYS`, `token_verifier` solo `TOKEN_HMAC_KEYS` y `throttle_digest` solo `THROTTLE_HMAC_KEYS`; cambiar una clave no altera los resultados de las otras dos funciones.
  - Un token de `account_activation` no verifica como `password_reset`.
- [X] T017 [P] Prueba unitaria TS-U05 en `backend/tests/unit/test_codes.py`:
  - El código de recuperación tiene **28 caracteres** del alfabeto base32 de Crockford (al menos 128 bits) y se muestra como 7 grupos de 4 separados por `-`.
  - La normalización acepta minúsculas, espacios y guiones y mapea `I`/`L`→`1` y `O`→`0`.
  - No hay duplicados en 10⁵ muestras.
  - El código de verificación tiene 8 caracteres en base32 de Crockford.
- [X] T018 [P] Prueba unitaria TS-U01 en `backend/tests/unit/test_password_hasher.py`: el hash empieza por `$argon2id$v=19$m=65536,t=3,p=1` y `PASSWORD_HASHERS` contiene un único hasher
- [X] T019 [P] Conformidad de sesión TS-SC01–SC04 en `backend/tests/session_conformance/test_schema_and_storage.py`:
  - **SC01**: `iam_usersession` no tiene columna `session_key` y `django_session` no existe.
  - **SC02**: claves de 256 bits URL-safe sin colisiones en 10⁴.
  - **SC03**: `key_verifier` coincide con `v1$[0-9a-f]{64}`, mide como máximo 72 caracteres y se cumple la restricción `CHECK` de versión.
  - **SC04**: con `connection.execute_wrapper`, el valor de la cookie nunca aparece en el SQL ni en los parámetros durante el ciclo csrf → login → peticiones → logout.
- [X] T020 [P] Conformidad de sesión TS-SC05–SC10 en `backend/tests/session_conformance/test_lifecycle.py`:
  - **SC05**: una cookie aleatoria, mal formada o de una versión retirada produce sesión vacía y clave nueva, y la presentada no se adopta.
  - **SC06**: un identificador presentado antes de autenticarse nunca se adopta, y la clave rota de `pre_auth` a `full` y tras los cambios de MFA.
  - **SC07**: los datos modificados persisten y `expire_date` **no** se extiende (es absoluta).
  - **SC08**: 15 min sin actividad según `last_activity_at` (reloj simulado) dan 401; actividad cada 10 min durante 1 h mantiene la sesión válida.
  - **SC09**: 8 h desde el `created_at` inicial con actividad continua dan 401, y `cycle_key` hereda `created_at` (I3).
  - **SC10**: `revoke_all`, el borrado por `public_id` y el logout dejan la fila inexistente y la siguiente petición da 401.
- [X] T021 [P] Conformidad de sesión TS-SC11–SC14 en `backend/tests/session_conformance/test_concurrency_rotation.py`:
  - **SC11** (`transactional_db`, dos conexiones): una revocación durante una petición en curso produce `SessionInterrupted` sin resurrección; no hay colisiones en creaciones simultáneas.
  - **SC12**: tras activar `v2`, las sesiones `v1` siguen válidas y las nuevas usan `v2`; `iam_rotate_session_key --retire v1` → 401; la rotación de emergencia → todas 401.
  - **SC13**: los métodos asíncronos lanzan `NotImplementedError` y el acceso por `session_key=` lanza `FieldError`.
  - **SC14**: el volcado de la base de datos tras la suite no contiene ninguna cookie emitida.
- [X] T134 [P] Conformidad de sesión TS-SC15–SC20 en `backend/tests/session_conformance/test_cookie_emission.py` (correcciones C2, I1 de la revisión 3 e I3):
  - **SC15**: en GET y POST autenticados que no modifican la sesión (p. ej. `GET /auth/session`, `GET /users/me/profile`), la respuesta **no** contiene `Set-Cookie: __Host-sf_session`. Sí aparece solo en la creación, el login, la elevación de `pre_auth` a `full` y la rotación tras cambios de MFA, y como borrado en el logout.
  - **SC16**: tras una petición autenticada con ≥ 60 s desde la anterior (reloj simulado), `last_activity_at` avanza mientras `session_data`, `expire_date` y `key_verifier` quedan idénticos byte a byte, y `request.session.modified` es falso; con menos de 60 s, no hay escritura.
  - **SC19** (corrección I1): `GET /auth/csrf` y un `POST /auth/login` con credenciales erróneas crean **0** filas `UserSession` (recuento antes y después) y no emiten `Set-Cookie: __Host-sf_session`; solo aparece `__Host-sf_csrftoken`. Un POST anónimo sin `X-CSRFToken` sigue dando **403**, y con el token válido se procesa sin crear sesión si las credenciales fallan.
  - **SC20** (corrección U3), a nivel de motor y permisos:
    - Una sesión `pre_auth` construida con `_sf_pending_user_id` persiste `user_id` igual al usuario pendiente, `auth_level = "pre_auth"` y `request.user` anónimo.
    - `IsFullyAuthenticated` la deniega (401) en una ruta protegida de prueba.
    - `revoke_all(user)` borra a la vez sus filas `pre_auth` y `full`, y las cookies de ambas dan 401 o sesión vacía.
    - `pre_auth` caduca a los 5 min (10 en un alta obligatoria) con reloj simulado.
    - Al pasar a `full`, `_sf_pending_user_id` desaparece de `session_data` y `user_id` se mantiene.
  - **SC18** (corrección I3): una sesión `pre_auth` creada en t₀ y elevada a `full` en t₀ + 9 min (reloj simulado) da **401 en t₀ + 8 h + 1 s**, con actividad cada 10 min. La fila `full` conserva el mismo `created_at` que la `pre_auth` y `expire_date = created_at + 8 h`. Una rotación por cambio de MFA en t₀ + 4 h no mueve `created_at` ni `expire_date`. Sin actividad, la sesión sigue cortando a los 15 min.
  - **SC17**: una sesión con `user_id` caducada por inactividad o por el límite absoluto y reutilizada genera exactamente 1 `session_expired`, con su motivo (`idle`, `absolute` o `pre_auth_timeout`). Una cookie aleatoria, mal formada, inexistente, de versión retirada o de una sesión ya purgada genera **0** eventos.
- [X] T022 [P] Seguridad TS-S16/TS-S26 en `backend/tests/security/test_db_privileges.py`, conectando como `securefin_app`:
  - UPDATE, DELETE y TRUNCATE sobre `securefin.audit_securityevent` fallan, y `has_table_privilege('securefin_app','securefin.audit_securityevent','UPDATE')` es falso.
  - `ALTER TABLE` y `DROP TRIGGER` fallan.
- [X] T023 [P] Seguridad TS-S05/S06/S07 en `backend/tests/security/test_csrf_cors.py`: se recorren **todas** las rutas del `URLResolver` con métodos POST, PUT, PATCH y DELETE; sin `X-CSRFToken` dan 403; ninguna respuesta incluye `Access-Control-Allow-Origin`; un `Origin` ajeno se rechaza. La prueba crece sola con cada ruta nueva.
- [X] T024 [P] Seguridad TS-S23 en `backend/tests/security/test_route_inventory.py`: la ruta `/admin/` de Django da 404 y no existe ninguna ruta anónima que cree usuarios con rol `admin` o `auditor`
- [X] T025 [P] Integración TS-I11 en `backend/tests/integration/test_tokens.py`:
  - Emisión y canje de un solo uso; uno nuevo invalida los anteriores del mismo usuario y propósito.
  - Un token alterado o de otro propósito se rechaza.
  - **Caducidades con reloj simulado**: `account_activation` válido a las 23:59:59 h y rechazado a las 24:00:01 h; `password_reset` válido a los 14:59 min y rechazado a los 15:01 min (FR-046).
  - Un canje concurrente con `select_for_update` no admite doble uso.
- [X] T026 [P] Integración TS-I18/TS-I12/TS-I13 en `backend/tests/integration/test_outbox.py`:
  - La tabla `iam_outboxmessage` no contiene tokens, códigos ni cuerpos de correo.
  - Con SMTP caído: reintentos con espera exponencial, `failed` tras 5 intentos y evento `email_delivery_failed` sin secretos.
  - Los correos solo van al backend configurado (en las pruebas, `locmem`).

### Implementación fundamental

- [X] T027 [P] Implementar `backend/apps/core/keys.py`, validando en el `AppConfig.ready()` de `backend/apps/core/apps.py` (R8):
  - Lee los secretos de `/run/secrets/*`.
  - `SESSION_HMAC_KEYS`, `TOKEN_HMAC_KEYS`, **`THROTTLE_HMAC_KEYS`** y `TOTP_ENCRYPTION_KEYS` son mapas versionados con una versión activa y las anteriores aceptadas: **una clave por propósito criptográfico** (C1).
  - Valida al arrancar presencia, al menos 32 bytes por versión y que **todas las claves y versiones sean distintas entre sí**, y falla de forma cerrada.
  - Si `SECUREFIN_PROCESS_ROLE=runtime` y `DB_USER` es `securefin_owner`, se niega a arrancar (U1).
- [X] T028 [P] Implementar los módulos de `core`:
  - `backend/apps/core/clock.py` con `now()` inyectable.
  - `backend/apps/core/middleware.py` con un `RequestIdMiddleware` que genera un UUID por petición.
  - `backend/apps/core/logging.py` con un formateador JSON y un filtro de redacción de las claves `password`, `token`, `secret`, `code`, `otp`, `session`, `cookie` y `authorization`.
- [X] T029 [P] Implementar `backend/apps/iam/crypto/hmac_verifiers.py` (R2, R7, R12):
  - `session_verifier(version, key)` → `f"{version}${hex(HMAC-SHA-256(SESSION_HMAC_KEYS[version], 'securefin:session:' + key))}"`.
  - `token_verifier(purpose, token, version)` con `TOKEN_HMAC_KEYS`.
  - `throttle_digest(email, version)` → `HMAC-SHA-256(THROTTLE_HMAC_KEYS[version], "throttle:acct:" + email normalizado)`. **Nunca** usa `TOKEN_HMAC_KEYS` ni `SESSION_HMAC_KEYS` (C1).
  - `verify()` con `hmac.compare_digest`.
- [X] T030 [P] Implementar `backend/apps/iam/crypto/codes.py`: `generate_recovery_code()` (28 caracteres de `secrets.choice` sobre base32 de Crockford, 140 bits), `format_code()` (7×4 con `-`), `normalize_code()` y `generate_verification_code()` (8 caracteres) (R6, R11)
- [X] T031 Crear el modelo `User` en `backend/apps/iam/models/user.py`, más su manager y la migración inicial en `backend/apps/iam/migrations/0001_initial.py` (data-model → User):

  | Campo | Restricción |
  |---|---|
  | `id` | uuid PK |
  | `email` | varchar(254), "Normalizado a minúsculas; único sin distinguir mayúsculas; ficticio" (`UniqueConstraint(Lower("email"))`) |
  | `name` | varchar(100), "1–100 caracteres, sin caracteres de control" |
  | `password` | varchar(128) |
  | `role` | enum `client` \| `admin` \| `auditor` |
  | `status` | enum `pending_activation` \| `active` \| `deactivated` |
  | `created_at`, `last_login_at`, `password_changed_at` | — |

  Sin `is_staff`, `is_superuser` ni grupos.
- [X] T032 [P] Implementar `backend/apps/iam/policies/hashers.py` con `SecureFinArgon2Hasher` (subclase de `Argon2PasswordHasher`; `memory_cost=65536`, `time_cost=3`, `parallelism=1`). No reducir sin aprobación (R4).
- [X] T033 Crear el modelo `UserSession` en `backend/apps/iam/models/session.py` y su migración (data-model → UserSession). **No hay ningún campo `session_key`**.

  | Campo | Restricción |
  |---|---|
  | `key_verifier` | varchar(72) PK |
  | `key_version` | varchar(6), indexado, `CHECK (key_verifier LIKE key_version \|\| '$%')` |
  | `session_data` | text |
  | `expire_date` | timestamptz indexado; **caducidad absoluta nunca extendida**, siempre desde el `created_at` inicial: `created_at + 5/10 min` (`pre_auth`), `created_at + 8 h` (`full` y demás) |
  | `public_id` | uuid único |
  | `user` | FK nulo indexado |
  | `auth_level` | varchar(10): `pre_auth` \| `full` (no se persisten sesiones anónimas; I1) |
  | `created_at` | **Creación inicial**; base del límite de 8 h (FR-011); se hereda en cada rotación |
  | `last_activity_at` | Base de la inactividad de 15 min; renovado en el servidor sin tocar `session_data` |
  | `authenticated_at` | nulo; momento del paso a `full`; informativo, sin efecto en la caducidad |
  | `ip_address` | inet nulo |
  | `user_agent` | varchar(200) nulo |

  Índices `(user, expire_date)`, `key_version` y `public_id`.
- [X] T034 Implementar el motor de sesión en `backend/apps/iam/sessions/store.py`, siguiendo la tabla de R2.4 (subclase de `db.SessionStore`, `get_model_class()` → `UserSession`):

  | Método | Comportamiento |
  |---|---|
  | `_get_new_session_key` | `secrets.token_urlsafe(32)` |
  | `create` | Reintento ante `IntegrityError` |
  | `create_model_instance` | Verificador de la versión activa + metadatos desde los datos de sesión: `user_id` sale de **`_sf_pending_user_id`** en `pre_auth` y de `_auth_user_id` en `full` (U3), más `auth_level` y `authenticated_at`. Una sesión sin `pre_auth` ni `full` no se persiste: lanza un error de programación, porque ninguna vista escribe datos de sesión antes de validar la contraseña (I1) + `expire_date` **absoluta** calculada siempre desde el `created_at` inicial (nunca desde "ahora") |
  | `save` | Solo se invoca con la sesión modificada (`SESSION_SAVE_EVERY_REQUEST = False`); `force_update` sin upsert; `UpdateError` si la fila fue revocada |
  | `load` / `_get_session_from_db` | Busca por verificador de las versiones aceptadas **sin filtrar por fecha**. Si la fila existe y `expire_date ≤ now` o `now − last_activity_at > 15 min`: la borra y, solo si tiene `user_id`, registra `session_expired` (motivo `idle`, `absolute` o `pre_auth_timeout`) con `audit.services.record_event`. Sin fila: ningún evento. En ambos casos, `_session_key = None` |
  | `touch(request)` (nuevo) | Si han pasado ≥ 60 s desde `last_activity_at`: `UserSession.objects.filter(key_verifier=…).update(last_activity_at, ip_address, user_agent)`; **no** marca `modified`, no cambia `session_data` ni `expire_date` y no provoca `Set-Cookie` |
  | `exists` / `delete` | Por verificadores |
  | `cycle_key` | La fila nueva **hereda el `created_at` inicial** (también de `pre_auth` a `full` y en el login) y recalcula `expire_date = created_at + 8 h` para `full`. Ninguna rotación reinicia el límite (I3) |
  | `clear_expired` | Por `expire_date` o por `created_at` de más de 8 h |
  | `aload`, `asave`, `acreate`, `aexists`, `adelete`, `acycle_key`, `aclear_expired` | Lanzan `NotImplementedError` |
- [X] T035 Implementar las piezas complementarias del motor de sesión:
  - `backend/apps/iam/sessions/middleware.py` con un `SessionLifetimeMiddleware`, situado después de `SessionMiddleware`. Es la segunda capa de inactividad (15 min) y del límite absoluto (8 h), y llama a `SessionStore.touch()` para renovar `last_activity_at`, `ip_address` y `user_agent` (truncado a 200) **sin reemitir la cookie** (C2).
  - `backend/apps/iam/services/session_admin.py` con `revoke_all(user, except_current=None)` (DELETE por `user_id` de **todas** las filas del usuario, tanto `pre_auth` como `full`; evento `sessions_revoked` con el recuento por nivel; U3).
  - El comando `backend/apps/iam/management/commands/iam_rotate_session_key.py --retire vN`, que se niega si `vN` es la activa.
- [X] T036 Crear `SecurityEvent` en `backend/apps/audit/models.py` (data-model → SecurityEvent):
  - Campos `id` uuid, `occurred_at` indexado, `event_type` enum con los **32 tipos literales** del catálogo, `outcome` (`success` \| `failure` \| `denied`), `actor_id`, `actor_role`, `target_type`, `target_id`, `source_ip`, `request_id` y `metadata` jsonb.
  - El modelo impide `save()` sobre registros existentes y `delete()`.
- [X] T037 Implementar `backend/apps/audit/services.py` con `record_event(event_type, outcome, actor, target, source_ip=None, metadata=None)`: lista permitida de claves de `metadata` por tipo, rechazo de las claves `password`, `token`, `secret`, `code`, `otp`, `session` y `cookie`, y `request_id` tomado del middleware. Debe invocarse dentro de la transacción del llamador.
- [X] T038 Crear la migración `backend/apps/audit/migrations/0002_protect_audit.py` (R14) con `RunSQL`:
  - Función y trigger `BEFORE UPDATE OR DELETE ... FOR EACH ROW` y trigger `BEFORE TRUNCATE ... FOR EACH STATEMENT`, ambos lanzando una excepción.
  - `REVOKE UPDATE, DELETE, TRUNCATE ON securefin.audit_securityevent FROM securefin_app`.
- [X] T039 [P] Implementar `backend/apps/iam/policies/matrix.py`: la "Matriz de permisos" de spec.md traducida a `ROLE_PERMISSIONS` y `ROLE_MFA_REQUIRED` (`client`: opcional; `admin` y `auditor`: obligatorio; cualquier rol nuevo, obligatorio por defecto)
- [X] T040 Implementar `backend/apps/iam/api/permissions.py` y `backend/apps/iam/api/exceptions.py` (R15, `contracts/iam-api.md` §1):
  - **Permisos**: `IsFullyAuthenticated` (`auth_level == "full"`, usuario `active` y MFA cumplido según `ROLE_MFA_REQUIRED`), `HasRolePermission(perm)` e `IsResourceOwner`. Alias `me` y consultas filtradas por propietario; un recurso ajeno da 404 y evento `authz_denied`.
  - **Configuración DRF**: `DEFAULT_PERMISSION_CLASSES = [IsFullyAuthenticated]` (denegar por defecto) y `DEFAULT_AUTHENTICATION_CLASSES = [SessionAuthentication]`.
  - **Errores**: manejador con formato `{"error": {"code", "message"}}` y el 401 literal `{"code": "auth_failed", "message": "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."}`.
- [X] T041 Implementar `backend/apps/iam/api/urls.py` (montado en `/api/v1/`) y `backend/apps/iam/api/views/csrf.py`: `GET /auth/csrf` con `ensure_csrf_cookie` (204), y el decorador `anonymous_state_changing` (= `csrf_protect` + `AllowAny` explícito) para las vistas anónimas
- [X] T042 Crear `OneTimeToken` en `backend/apps/iam/models/tokens.py` (data-model):
  - Campos `purpose` enum (`account_activation` de 24 h \| `password_reset` de 15 min, FR-046), `verifier` char(64) único, `key_version` varchar(6), `created_at`, `expires_at`, `used_at` nulo e `invalidated_at` nulo.
  - Servicio `backend/apps/iam/services/tokens.py` con `issue(user, purpose)` (invalida los pendientes del mismo usuario y propósito y devuelve el token en claro **solo en memoria**) y `redeem(token, purpose)` (`select_for_update`, `compare_digest`, un solo uso; caducidad desde `TOKEN_TTL = {"account_activation": 24h, "password_reset": 15min}`).
- [X] T043 Crear `OutboxMessage` en `backend/apps/iam/models/outbox.py` (data-model), **sin campos de token, código ni cuerpo**:
  - `kind` enum `account_activation` \| `password_reset` \| `mfa_reset_challenge` \| `mfa_reset_notice`.
  - `user` FK, `related_id` uuid nulo, `status` enum `pending` \| `sending` \| `sent` \| `failed`, `attempts` smallint (máximo 5), `next_attempt_at`, `created_at` y `sent_at`.
- [X] T044 Implementar el outbox (R9):
  - `backend/apps/iam/services/outbox.py`: `enqueue(kind, user, related_id=None)` y un registro de *handlers* por `kind`, que cada historia completa.
  - `backend/apps/iam/management/commands/iam_deliver_outbox.py`: bucle con `select_for_update(skip_locked=True)`; el *handler* genera el secreto **en el momento de la entrega** y compone el correo en memoria; envío SMTP; espera exponencial; `failed` tras 5 intentos con evento `email_delivery_failed`; opción `--once`.
- [X] T045 [P] Crear la base del frontend:
  - `frontend/src/api/client.js`: `fetch` con `credentials: "same-origin"`, `X-CSRFToken` leído de la cookie `__Host-sf_csrftoken` y análisis del formato de error uniforme.
  - `frontend/src/lib/fragmentToken.js` (R7): lee `location.hash` en el primer render, ejecuta `history.replaceState(null, "", location.pathname + location.search)` y devuelve el token solo para guardarlo en el estado del componente.
  - Enrutador base en `frontend/src/App.jsx`.

**Checkpoint**: la base está lista. Las suites T015–T026 y T134 pasan en verde y las historias pueden empezar.

---

## Phase 3: User Story 1 - Registro, inicio y cierre de sesión de clientes (Priority: P1) 🎯 MVP

**Goal**: un cliente ficticio se registra, inicia sesión con contraseña Argon2id, accede a su área y
cierra sesión. Los errores de autenticación son genéricos.

**Independent Test**: registrar un cliente, iniciar sesión, consultar `/auth/session`, cerrar sesión
y comprobar el 401 posterior. Corresponde a los escenarios V1–V6 de quickstart.md.

### Tests for User Story 1 ⚠️ (escribir primero; deben fallar)

- [X] T046 [P] [US1] Prueba unitaria TS-U02 en `backend/tests/unit/test_password_validators.py`: se rechazan 14 caracteres, 129 caracteres, contraseñas comunes, las que contienen el email o el nombre y `securefin-gateway-2026`; se aceptan 15 caracteres con espacios o Unicode; la normalización NFKC es equivalente en registro y login; no hay reglas de composición
- [X] T047 [P] [US1] Contrato TS-C01 (parte US1) en `backend/tests/contract/test_auth_contract.py`: `POST /auth/register` (201 `{"status": "registered"}`), `POST /auth/login` (los tres valores de `status` y 401 genérico), `POST /auth/logout` (204) y `GET /auth/session` (campos de `UserSummary` y `session`); sin campos sensibles; `Cache-Control: no-store`
- [X] T048 [P] [US1] Integración TS-I01–I05 en `backend/tests/integration/test_auth_flow.py`: registro, login, logout, `/auth/session` y rotación de la clave de sesión en el login (TS-I05)
- [X] T049 [P] [US1] Seguridad en `backend/tests/security/test_us1_auth.py`:
  - **TS-S04**: cookie `__Host-sf_session` con `HttpOnly`, `Secure`, `SameSite=Strict` y `Path=/`.
  - **Enumeración**: el cuerpo del 401 es idéntico para un usuario inexistente y para una contraseña errónea.
  - **TS-S20**: `role`, `status` o `mfa_*` en el registro dan 400.
  - **TS-S22**: con una contraseña de 129 caracteres, 400 **sin** invocar el hasher (mock).
  - Un Administrador o Auditor sin MFA **nunca** recibe una sesión `full`.
- [X] T050 [P] [US1] Aceptación TS-A01 en `backend/tests/acceptance/test_us1_registration_login.py`: una prueba por cada escenario 1–3 y 5–8 de US1 de spec.md. El escenario 4 (gestores de contraseñas, pegar y autocompletar) es comportamiento del navegador y lo cubre T133 (G3)
- [X] T131 [P] [US1] Seguridad TS-S27 en `backend/tests/security/test_login_enumeration.py` (NFR-003; corrección G1):
  - Se comparan 200 logins de usuarios **existentes con contraseña errónea** y 200 de usuarios **inexistentes**, con identificadores distintos para no activar los retrasos por cuenta y la limitación por IP desactivada en el *fixture*.
  - Comportamiento externo equivalente: mismo estado (401), cuerpo idéntico byte a byte, mismo conjunto de nombres de cabecera (salvo `Date`) y ninguno de los dos emite `Set-Cookie: __Host-sf_session`.
  - Diferencia media de tiempo inferior a **100 ms**, con mediana y percentil 95 registrados en el informe.
  - El camino del usuario inexistente ejecuta el hash ficticio con los mismos parámetros (mock espía).
  - La comparación de la recuperación sigue en T109.
- [X] T133 [P] [US1] E2E TS-E01 con Playwright en `frontend/tests/e2e/password-fields.spec.js` (FR-005, escenario 4 de US1; correcciones G3 e I1). Comprueba **solo los formularios de US1**: `/register` y `/login`. `/activate` lo prueba T135 (US4) y `/reset`, T136 (US7):
  - **Atributos**: en `/register`, el email tiene `autocomplete="username"` y la contraseña `autocomplete="new-password"`; en `/login`, `username` y `current-password`.
  - **Pegado**: se escribe la contraseña en el portapapeles y se pega con `Control+V`/`Meta+V`; el campo contiene el valor y ningún manejador `paste` lo cancela (`defaultPrevented === false`).
  - **Compatibilidad con gestores**: cada campo está dentro de un `<form>` con botón `submit`, tiene `name`/`id` estables y `type="password"`, no usa `autocomplete="off"` y no tiene `readonly` ni `maxlength` inferior a 128.
  - Se verifican los requisitos de marcado de los gestores; el autocompletado real de un gestor concreto no se puede automatizar y se documenta así en `docs/security/evidence/`.

### Implementation for User Story 1

- [X] T051 [P] [US1] Implementar `backend/apps/iam/policies/password_validators.py` (R4) y `backend/apps/iam/policies/data/blocklist.txt` (fuente documentada en la cabecera):
  - `MaximumLengthValidator(128)` y `ServiceTermsBlocklistValidator` (términos "securefin" y "gateway", más el archivo de bloqueo local).
  - Configurar en `backend/config/settings/base.py` el ajuste `AUTH_PASSWORD_VALIDATORS` con `MinimumLengthValidator(15)`, `UserAttributeSimilarityValidator` (`email`, `name`), `CommonPasswordValidator` y los dos validadores propios, **sin** `NumericPasswordValidator`.
  - Función `normalize_password()` con NFKC.
- [X] T052 [P] [US1] Implementar `backend/apps/iam/api/serializers/auth.py`:
  - `RegisterSerializer`: solo `email` (254), `name` (1–100, sin caracteres de control) y `password` (máximo 128 **antes** de hashear); cualquier otro campo da 400.
  - `LoginSerializer` con `email` y `password`.
- [X] T053 [US1] Implementar `backend/apps/iam/services/registration.py`: `register(email, name, password)` normaliza el email a minúsculas, fija **siempre** `role = client` y `status = active`, aplica los validadores y registra `account_registered`. Ante un identificador duplicado, error neutro (FR-001–FR-006).
- [X] T054 [US1] Implementar `backend/apps/iam/services/authentication.py` (FR-007–FR-011, FR-025):
  - `password_login(request, email, password)`: verificación Argon2id, o un hash ficticio con los mismos parámetros si la cuenta no existe; fallo genérico para inexistente, contraseña incorrecta, `pending_activation` o `deactivated`.
  - Si el rol tiene `ROLE_MFA_REQUIRED` y no hay MFA, se devuelve `mfa_enrollment_required` **sin** `login()` (US3 completa el alta).
  - Si no, `django.contrib.auth.login()` (que rota la clave), `auth_level = "full"`, `authenticated_at = now` y `last_login_at`.
  - Eventos `login_succeeded` y `login_failed`.
- [X] T055 [US1] Implementar `backend/apps/iam/api/views/auth.py`: `POST /auth/register`, `POST /auth/login` y `POST /auth/logout` (con `anonymous_state_changing` donde corresponda; el logout borra la fila y registra `logout`), y `GET /auth/session` (`idle_expires_at` y `absolute_expires_at`). Rutas en `backend/apps/iam/api/urls.py`.
- [X] T056 [P] [US1] Crear `frontend/src/pages/Register.jsx`, `frontend/src/pages/Login.jsx` y `frontend/src/pages/Home.jsx` (FR-005; corrección U1):
  - **`/register`**: un `<form>` con botón `type="submit"`; email con `autocomplete="username"`, `type="email"` y `name`/`id` estables; contraseña con `type="password"` y `autocomplete="new-password"`.
  - **`/login`**: un `<form>` con botón `type="submit"`; email con `autocomplete="username"`; contraseña con `autocomplete="current-password"`.
  - En todos los campos de contraseña: sin manejadores que cancelen `paste`, sin `autocomplete="off"`, sin `readonly` y **ningún `maxlength` inferior a 128**, para mantener la compatibilidad con gestores de contraseñas.
  - Mensajes de validación del servidor y mensaje genérico ante el 401.
- [X] T057 [P] [US1] Escribir `docs/security/passwords.md` (Argon2id: parámetros, por qué y metodología de calibración; política NIST, NFKC y lista de bloqueo) y `docs/security/sessions.md` (motor de sesión con verificadores HMAC, cookie `__Host-`, CSRF sin CORS, inactividad, límite absoluto, rotación y revocación) (FR-049)

**Checkpoint**: US1 funciona de forma independiente (MVP).

---

## Phase 4: User Story 2 - Acceso según rol y solo a recursos propios (Priority: P2)

**Goal**: RBAC de función y de objeto en el servidor; cada usuario solo opera sobre su perfil, sus
sesiones y su configuración de seguridad.

**Independent Test**: con usuarios precargados de cada rol, el Cliente A intenta acceder a los
recursos del Cliente B (404 + `authz_denied`) y a funciones de otros roles (403). Escenarios V7–V9 y
V18 de quickstart.md.

### Tests for User Story 2 ⚠️

- [X] T058 [P] [US2] Seguridad TS-S01 en `backend/tests/security/test_authz_matrix.py`: prueba parametrizada **generada desde `ROLE_PERMISSIONS`** sobre todas las rutas registradas y los tres roles; las combinaciones fuera de la matriz dan 401, 403 o 404 según el contrato. Cubre automáticamente las rutas que añaden US3–US7.
- [X] T059 [P] [US2] Seguridad TS-S02 en `backend/tests/security/test_bola.py`: el Cliente A sobre `/users/{id_B}/profile`, `/users/{id_B}/sessions`, `DELETE /users/{id_B}/sessions/{public_id_B}` y `/users/{id_B}/security`, más identificadores secuenciales, aleatorios y mal formados → 404 sin revelar existencia y evento `authz_denied`
- [X] T060 [P] [US2] Contrato TS-C01 (parte US2) en `backend/tests/contract/test_users_contract.py`: `GET/PATCH /users/{id}/profile` (PATCH solo con `name`; otros campos → 400), `GET /users/{id}/sessions` (campos `public_id`, `created_at`, `last_activity_at`, `ip_address`, `user_agent` y `current`; nunca el verificador), `DELETE /users/{id}/sessions/{public_id}` (204) y `GET /users/{id}/security`
- [X] T061 [P] [US2] Aceptación TS-A02 en `backend/tests/acceptance/test_us2_access_control.py`: escenarios 1, 2, 6 y 7 de US2; los escenarios 3–5 se validan con T058 cuando existen las rutas de US4 y US6

### Implementation for User Story 2

- [X] T062 [P] [US2] Implementar `backend/apps/iam/api/serializers/users.py`: `ProfileSerializer` (solo `name` editable; `role`, `status`, `email` y `mfa_*` dan 400; FR-018), `SessionSerializer` (expone `public_id` y nunca `key_verifier`) y `SecuritySerializer`
- [X] T063 [US2] Implementar `backend/apps/iam/api/views/users.py` con `HasRolePermission` e `IsResourceOwner` (consultas siempre filtradas por `request.user`):
  - `GET/PATCH /users/{user_id}/profile`.
  - `GET /users/{user_id}/sessions`.
  - `DELETE /users/{user_id}/sessions/{public_id}`: borra la fila; una sesión ajena da 404.
  - `GET /users/{user_id}/security`: `mfa_enabled`, `mfa_required` y `recovery_codes_remaining`.
- [X] T064 [US2] Registrar las rutas `/users/{user_id}/…` con el alias `me` en `backend/apps/iam/api/urls.py` y confirmar que T058 y T059 pasan
- [X] T065 [P] [US2] Crear `frontend/src/pages/Profile.jsx` y `frontend/src/pages/Sessions.jsx` (listar las propias sesiones y revocar otra sesión)
- [X] T066 [P] [US2] Escribir `docs/security/authorization.md`: matriz de permisos, denegar por defecto, BFLA frente a BOLA, respuesta 404 sin revelar existencia y por qué el frontend no es una frontera de confianza (FR-049)

**Checkpoint**: US1 y US2 funcionan de forma independiente.

---

## Phase 5: User Story 3 - Segundo factor TOTP y códigos de recuperación (Priority: P3)

**Goal**: alta de TOTP con secreto cifrado, login en dos pasos (`pre_auth`), 10 códigos de
recuperación de 140 bits y MFA obligatorio para Administrador y Auditor.

**Independent Test**: alta de TOTP para un usuario ficticio; login con código válido (acceso),
repetido (401) o con código de recuperación usado dos veces (200 y luego 401); un Auditor sin MFA no
accede a nada protegido. Escenarios V10–V12 de quickstart.md.

### Tests for User Story 3 ⚠️

- [X] T067 [P] [US3] Pruebas unitarias TS-U03/U04 en `backend/tests/unit/test_aead.py`: cifrar y descifrar con AAD `"securefin:totp:v1:" + user.id`; un texto cifrado trasladado a otro usuario falla la autenticación GCM; dos cifrados del mismo secreto usan nonces distintos de 12 bytes
- [X] T068 [P] [US3] Integración TS-I09/TS-I10 en `backend/tests/integration/test_mfa.py`:
  - Un código TOTP repetido en su ventana da 401 y se acepta ±1 intervalo.
  - Los códigos de recuperación son de un solo uso; uno de un lote anterior se rechaza.
  - Dos peticiones concurrentes con el mismo código: solo una tiene éxito (`select_for_update`).
  - El alta `pending` caduca a los 10 min.
- [X] T069 [P] [US3] Seguridad TS-S15 en `backend/tests/security/test_pre_auth.py` (con los endpoints reales; complementa a SC20 de T134):
  - **Usuario con MFA pendiente**: tras una contraseña válida, la fila `pre_auth` tiene `user_id` del usuario (desde `_sf_pending_user_id`) y `request.user` anónimo.
  - **Sin acceso**: con esa sesión, **todas** las rutas protegidas dan 401, incluidas `/users/me/*`, `/admin/*` y `/audit/*`; solo responden `/auth/login/mfa`, `/auth/login/enroll/*`, `/auth/login/mfa-reset-request` y `/auth/logout`.
  - **Revocación de `pre_auth`**: un cambio de rol, una desactivación o `revoke_all` sobre ese usuario hace que la sesión `pre_auth` dé 401 en `/auth/login/mfa`.
  - **Revocación de `full`**: un `revoke_all` posterior a completar el MFA invalida también la sesión `full`.
  - **Expiración**: `pre_auth` caduca a los 5 min (10 en un alta obligatoria), con reloj simulado.
  - **Rotación**: la clave rota al pasar de `pre_auth` a `full`.
- [X] T070 [P] [US3] Contrato TS-C01 (parte US3) en `backend/tests/contract/test_mfa_contract.py`: `/auth/login/mfa`, `/auth/login/enroll/setup`, `/auth/login/enroll/confirm` (10 códigos de 28 caracteres) y `/users/{id}/mfa/totp/{setup,confirm,disable}`, `/users/{id}/mfa/recovery-codes/regenerate`; `Cache-Control: no-store` en las respuestas con secreto o códigos
- [X] T071 [P] [US3] Aceptación TS-A03 en `backend/tests/acceptance/test_us3_mfa.py`: una prueba por cada escenario 1–10 de US3

### Implementation for User Story 3

- [X] T072 [P] [US3] Implementar `backend/apps/iam/crypto/aead.py` con `encrypt_totp_secret(user_id, secret)` y `decrypt_totp_secret(user_id, nonce, ciphertext, key_version)`: AES-256-GCM (`cryptography`), nonce aleatorio de 96 bits por operación, AAD `"securefin:totp:v1:" + str(user_id)` y la clave `TOTP_ENCRYPTION_KEYS[version]` (R5)
- [X] T073 [P] [US3] Crear `TOTPDevice` y `RecoveryCode` con su migración en `backend/apps/iam/models/mfa.py` (data-model):
  - **`TOTPDevice`**: `user` OneToOne; `status` enum `pending` \| `active`; `secret_ciphertext` bytea; `nonce` bytea(12); `key_version` varchar(6); `last_used_timestep` bigint nulo; `created_at` y `confirmed_at` ("un alta `pending` caduca a los 10 minutos").
  - **`RecoveryCode`**: `user` FK; `batch_id` uuid; `verifier` varchar(128); `status` enum `available` \| `used` \| `invalidated`; `created_at`; `used_at`.
- [X] T074 [US3] Implementar `backend/apps/iam/services/mfa.py` (FR-024–FR-027, FR-031):
  - `start_enrollment` genera un secreto de 160 bits con `secrets`, lo cifra y crea el dispositivo `pending`; devuelve `otpauth_uri`, `qr_svg_data_uri` (QR con `segno` en `data:image/svg+xml;base64`) y `secret_base32`.
  - `confirm_enrollment` (`pyotp`, SHA-1, 6 dígitos, 30 s, `valid_window=1`) activa el dispositivo y genera los códigos.
  - `verify_totp` acepta solo `timestep > last_used_timestep`.
  - `disable` solo para roles con MFA opcional y exige contraseña y código.
  - `reconfigure` exige contraseña e invalida el secreto y el lote anteriores.
  - Eventos `mfa_enabled`, `mfa_disabled`, `mfa_reconfigured` y `totp_rejected`.
- [X] T075 [US3] Implementar `backend/apps/iam/services/recovery_codes.py` (R6, FR-028–FR-030):
  - `generate_batch(user)`: 10 códigos de `codes.generate_recovery_code()`; verificador Argon2id (`argon2-cffi`, `memory_cost=19456`, `time_cost=2`, `parallelism=1`); invalida el lote anterior; devuelve los códigos en claro solo una vez.
  - `consume(user, raw)`: normaliza, usa `select_for_update` sobre los códigos `available` y los marca `used`; evento `recovery_code_used`.
  - `regenerate(user, password, totp)`: evento `recovery_codes_regenerated`.
- [X] T076 [US3] Ampliar `backend/apps/iam/services/authentication.py` con el flujo `pre_auth` (R13):
  - Tras una contraseña válida, si hay MFA activo → `pre_auth` (5 min, sin `login()`); si es un rol con MFA obligatorio sin MFA → `pre_auth` de alta (10 min). En ambos casos se crea la **primera** fila de sesión con `_sf_pending_user_id = user.id` y `_sf_auth_level = "pre_auth"`; `request.user` no se autentica (U3, I1).
  - Al completar el MFA o el alta, `login()` sustituye `_sf_pending_user_id` por `_auth_user_id` y la nueva fila hereda `created_at` (I3).
  - `complete_mfa(request, totp_code | recovery_code)` y `complete_enrollment` → `login()` (rota la clave), `full` y `authenticated_at`.
  - Las rutas permitidas en `pre_auth` son solo `/auth/login/mfa`, `/auth/login/enroll/*`, `/auth/login/mfa-reset-request` y `/auth/logout`.
- [X] T077 [US3] Aplicar FR-012 en `backend/apps/iam/services/mfa.py` y `backend/apps/iam/services/recovery_codes.py`: al activar, desactivar o reconfigurar el MFA, o al regenerar los códigos, `session_admin.revoke_all(user, except_current=request.session)` y `request.session.cycle_key()`, heredando el `created_at` inicial (el límite absoluto no se reinicia)
- [X] T078 [US3] Implementar `backend/apps/iam/api/serializers/mfa.py` y `backend/apps/iam/api/views/mfa.py` con `Cache-Control: no-store` en las respuestas con secreto o códigos y sus rutas en `backend/apps/iam/api/urls.py`:
  - `POST /auth/login/mfa`, `POST /auth/login/enroll/setup` y `POST /auth/login/enroll/confirm`.
  - `POST /users/{id}/mfa/totp/setup` (`{password}` si ya hay MFA activo), `POST /users/{id}/mfa/totp/confirm` y `POST /users/{id}/mfa/totp/disable` (403 para `admin` y `auditor`).
  - `POST /users/{id}/mfa/recovery-codes/regenerate`.
- [X] T079 [P] [US3] Implementar el comando `backend/apps/iam/management/commands/iam_rotate_totp_key.py --to vN`: recifra todos los `TOTPDevice` con la versión `vN` dentro de una transacción e informa del recuento (R8)
- [X] T080 [P] [US3] Crear `frontend/src/pages/MfaStep.jsx` (TOTP o código de recuperación), `frontend/src/pages/Enroll.jsx` (QR en `<img src=data:…>` y secreto en texto) y `frontend/src/components/RecoveryCodes.jsx`:
  - Los códigos se muestran una sola vez, con copiar y descarga `.txt` generada en el navegador con `Blob`.
  - Nunca se guardan en el almacenamiento del navegador.
- [X] T081 [P] [US3] Escribir `docs/security/mfa.md`: TOTP (parámetros y antirrepetición), AES-256-GCM con AAD y por qué no se usa un hash, códigos de recuperación de 140 bits con Argon2id, `pre_auth` y MFA obligatorio por rol (FR-049)

**Checkpoint**: US1–US3 funcionan de forma independiente.

---

## Phase 6: User Story 4 - Administración de usuarios, roles y reinicio de MFA (Priority: P4)

**Goal**: el Administrador gestiona usuarios y roles, crea cuentas que se activan por correo y
reinicia el MFA con el procedimiento verificable de R11. El primer y el último Administrador se
gestionan solo por consola.

**Independent Test**: un Administrador con MFA cambia un rol, desactiva una cuenta y completa un
reinicio de MFA; se comprueban los efectos inmediatos, los eventos y las notificaciones en el buzón,
y que un no administrador no puede hacerlo. Escenarios V3, V10, V15 y V16 de quickstart.md.

### Tests for User Story 4 ⚠️

- [X] T082 [P] [US4] Seguridad TS-S12 en `backend/tests/security/test_mfa_reset_abuse.py`, comprobando que se rechazan:
  - abrir un caso propio (403);
  - autorizar sin TOTP del Administrador, o por un Administrador distinto del que abrió (403);
  - un código caducado (más de 10 min) o reutilizado (409);
  - un cuarto intento (caso `cancelled` al tercer fallo);
  - una solicitud sin `pre_auth` (401) y la cuarta solicitud en 24 h (429).

  Además comprueba que la contraseña no cambia y que la respuesta nunca contiene el secreto ni los códigos.
- [ ] T083 [P] [US4] Integración TS-I14/TS-I17 en `backend/tests/integration/test_admin_and_console.py`:
  - `iam_bootstrap_admin` falla si ya hay un Administrador y no imprime tokens.
  - `iam_break_glass` falla si existe otro Administrador activo con MFA y registra `break_glass_executed` con el usuario del sistema operativo.
  - Con un fallo simulado de `record_event`, el cambio de rol y la desactivación se revierten (FR-044).
- [X] T084 [P] [US4] Contrato TS-C01 (parte US4) en `backend/tests/contract/test_admin_contract.py`: todas las rutas de `contracts/iam-api.md` §4, más `POST /auth/activate` y `POST /auth/login/mfa-reset-request`
- [ ] T139 [US4] Crear el *fixture* de Mailpit en `frontend/tests/e2e/fixtures/mailpit.js` para las E2E de US4, US7 y Polish (corrección U2):
  - **Acceso**: solo la API REST autenticada de Mailpit a través de Nginx en `https://127.0.0.1:8025` (CA de laboratorio efímera), con Basic Auth tomada de `MAILPIT_API_USER` y `MAILPIT_API_PASSWORD` (variables de entorno efímeras; si faltan, la prueba **falla**, no se omite).
  - **Funciones**:
    - `findMessage({to, subject})` → `GET /api/v1/messages` y filtrado por destinatario y asunto;
    - `extractToken(id)` → `GET /api/v1/message/{ID}` o `/api/v1/message/{ID}/raw` y extracción del fragmento `#token=` **solo en memoria**;
    - `deleteMessages(ids)` → `DELETE /api/v1/messages`.
  - **Prohibido**: imprimir tokens, URLs completas o cuerpos; escribirlos en archivos; adjuntarlos al informe; acceder a Mailpit por otra ruta.
  - Usado por T135, T136 y T122.
- [ ] T135 [P] [US4] E2E TS-E02 con Playwright en `frontend/tests/e2e/activate-form.spec.js` (FR-005, FR-021; correcciones I1 de la revisión 3, U1 y U2). Solo prueba el formulario de US4 (`/activate#token=…`), con el token real obtenido del correo de activación mediante el *fixture* de T139. Sin trazas, vídeos ni capturas; el token se consume en la prueba y el mensaje se borra al final:
  - campo de contraseña con `type="password"` y `autocomplete="new-password"`, dentro de un `<form>` con botón `submit` y con `name`/`id` estables;
  - pegado con `Control+V`/`Meta+V` permitido (`defaultPrevented === false`);
  - sin `autocomplete="off"` ni `readonly` y ningún `maxlength` inferior a 128;
  - al cargar, `location.hash` queda vacío **tras `history.replaceState`**, antes de enviar;
  - el envío consume el token y activa la cuenta (204); un segundo uso del mismo token falla.
- [ ] T085 [P] [US4] Aceptación TS-A04 en `backend/tests/acceptance/test_us4_admin.py`: una prueba por cada escenario 1–9 de US4

### Implementation for User Story 4

- [X] T086 [US4] Implementar `backend/apps/iam/services/admin_users.py` (FR-019, FR-020, FR-012, FR-044), con evento y revocación de sesiones dentro de la misma `transaction.atomic`:
  - `list_users` con filtros `role` y `status` y paginación.
  - `create_privileged_user(email, name, role ∈ {admin, auditor})`: `pending_activation`, contraseña inutilizable, `outbox.enqueue("account_activation")` y evento **`account_created_by_admin`** (actor = Administrador, objetivo = nueva cuenta, `metadata.role`) en la misma transacción (I1).
  - `change_role`, `deactivate` y `reactivate`: prohibido actuar sobre sí mismo (403) y bloqueo de fila sobre los Administradores activos para impedir dejar 0 (409).
- [X] T087 [US4] Registrar el *handler* `account_activation` del outbox en `backend/apps/iam/services/activation.py` y crear la vista `POST /auth/activate` en `backend/apps/iam/api/views/activation.py` (FR-021):
  - El *handler* ejecuta `tokens.issue(user, "account_activation")` (24 h) y envía el enlace `https://securefin.local/activate#token=…`. **Tras la entrega SMTP correcta** registra `activation_sent` (objetivo = usuario, sin token ni enlace) (I1).
  - `activate(token, password)` aplica los validadores, cambia el estado a `active` y registra `account_activated`.
  - La vista usa `anonymous_state_changing`; ante cualquier fallo, `400 invalid_token`.
- [X] T088 [P] [US4] Crear `MfaResetCase` y su migración en `backend/apps/iam/models/mfa_reset.py` (data-model):
  - **Campos**: `target_user`; `requested_by`; `request_verification` enum `password` \| `console`; `requested_at`; `opened_by` nulo; `request_channel` enum `in_person` \| `course_channel` nulo; `opened_at`; `challenge_verifier` varchar(128) nulo ("se borra al autorizar o cancelar"); `challenge_expires_at` ("Entrega + 10 min"); `challenge_attempts` ("Máximo 3"); `status` enum `requested` \| `pending_verification` \| `authorized` \| `cancelled` \| `expired`; `authorized_by`; `authorized_at`; `verification_method` varchar(64).
  - **Restricción**: un caso abierto por titular.
- [X] T089 [US4] Implementar `backend/apps/iam/services/mfa_reset.py` (R11, FR-032–FR-035):
  - **`request_reset`**: solo desde `pre_auth`; crea el caso `requested` con `request_verification = password`; como máximo 3 en 24 h; evento `mfa_reset_requested`; cierra la sesión `pre_auth`.
  - **`open_case`**: el Administrador tiene MFA activo y es distinto del titular; guarda el canal; encola `mfa_reset_challenge`; evento `mfa_reset_case_opened`.
  - ***Handler* `mfa_reset_challenge`**: código de 8 caracteres con `codes.generate_verification_code()`, verificador Argon2id (`memory_cost=19456`, `time_cost=2`, `parallelism=1`) y caducidad de 10 min **desde la entrega**.
  - **`authorize`**: el Administrador es quien abrió el caso; TOTP actual del Administrador; máximo 3 intentos; no caducado. Efectos en una única transacción: invalida el `TOTPDevice` y el lote de códigos, `revoke_all`, borra `challenge_verifier`, guarda `verification_method = "password+email_challenge+out_of_band:<canal>"`, registra `mfa_reset_authorized` (solicitante, autorizador y fechas) y encola `mfa_reset_notice`.
  - ***Handler* `mfa_reset_notice`** (registrado en el outbox; corrección I2): compone el correo de `contracts/iam-api.md` §8 con la fecha del reinicio, un aviso y qué hacer si no lo solicitó, sin datos del Administrador más allá del rol y sin enlaces con tokens.
  - **`cancel`**: evento `mfa_reset_cancelled`.
  - **Garantías**: nunca modifica la contraseña ni devuelve secretos.
- [X] T090 [US4] Implementar `backend/apps/iam/api/serializers/admin.py` y `backend/apps/iam/api/views/admin.py` (rutas en `backend/apps/iam/api/urls.py`), con `HasRolePermission` de Administrador e `IsFullyAuthenticated`:
  - `GET /admin/users`, `POST /admin/users`, `POST /admin/users/{id}/activation/resend`, `PATCH /admin/users/{id}/role`, `POST /admin/users/{id}/deactivate` y `/reactivate`.
  - `GET /admin/mfa-resets?status=requested`, `POST /admin/mfa-resets/{id}/open`, `/authorize` y `/cancel`.
  - `POST /auth/login/mfa-reset-request` (`pre_auth`).
- [ ] T091 [P] [US4] Implementar el comando `backend/apps/iam/management/commands/iam_bootstrap_admin.py --email --name`: solo si no existe ningún Administrador; crea la cuenta en `pending_activation` y encola la activación; sin contraseñas por argumentos ni tokens impresos; evento `bootstrap_admin_executed`; código de salida distinto de 0 si ya hay un Administrador (FR-022)
- [ ] T092 [P] [US4] Implementar el comando `backend/apps/iam/management/commands/iam_break_glass.py --email --reason` (FR-023):
  - Precondición: no existe otro Administrador activo con MFA.
  - Pide confirmación interactiva.
  - Efectos de FR-033 y `tokens.issue("password_reset")` encolado vía outbox.
  - Evento `break_glass_executed` con el usuario del sistema operativo; sin tokens impresos.
- [ ] T093 [P] [US4] Crear `frontend/src/pages/Activate.jsx` (usa `fragmentToken.js`, envía a `/auth/activate` y descarta el token). Su formulario es un `<form>` con botón `type="submit"` y un campo de contraseña con `type="password"`, `autocomplete="new-password"` y `name`/`id` estables; permite pegar (sin cancelar `paste`), no usa `autocomplete="off"` ni `readonly` y no tiene ningún `maxlength` inferior a 128 (U1). Crear también `frontend/src/pages/admin/Users.jsx`, `frontend/src/pages/admin/MfaResets.jsx` (abrir, autorizar con el código y el TOTP del Administrador, cancelar) y el botón "Perdí mi dispositivo y mis códigos" en `frontend/src/pages/MfaStep.jsx`
- [ ] T094 [P] [US4] Escribir `docs/security/admin-and-mfa-reset.md` (procedimiento de verificación de identidad de R11 paso a paso, autorización reforzada y garantías antiabuso) y `docs/security/console-procedures.md` (bootstrap, break-glass, rotación de claves y su ejecución solo en el entorno controlado) (FR-049)

**Checkpoint**: US1–US4 funcionan de forma independiente.

---

## Phase 7: User Story 5 - Protección frente a intentos repetidos (Priority: P5)

**Goal**: retrasos progresivos por cuenta (desde el 5.º fallo, con tope de 15 min), limitación por
IP y eventos de anomalía, sin bloqueo rígido y con el mismo comportamiento para cuentas
inexistentes.

**Independent Test**: una serie automatizada de fallos contra una cuenta y desde una IP sobre varias
cuentas; se comprueban los retrasos, su tope, su expiración y los eventos. Escenario V13 de
quickstart.md.

### Tests for User Story 5 ⚠️

- [ ] T095 [P] [US5] Integración TS-I15/TS-I16 en `backend/tests/integration/test_throttling.py`, con reloj simulado:
  - Secuencia de retrasos de 30, 60, 120, 240, 480 y 900 s, con 900 s como tope.
  - Reinicio tras un éxito y tras 30 min sin fallos.
  - Eventos `throttle_account_delay`, `throttle_ip_limited` y `credential_stuffing_suspected` (10 o más identificadores distintos en 15 min desde una IP).
- [ ] T096 [P] [US5] Seguridad TS-S13/TS-S14 en `backend/tests/security/test_bruteforce.py`: en 100 intentos rápidos, como máximo 5 se evalúan antes del primer retraso; los intentos durante el retraso se rechazan sin invocar el hasher (mock); el comportamiento es idéntico para un identificador inexistente; los fallos de TOTP y de código de recuperación cuentan
- [ ] T132 [P] [US5] Seguridad TS-S28 en `backend/tests/security/test_ip_rate_limits.py`: prueba **parametrizada** por ámbito de límite por IP (FR-037; correcciones G2 e I2). Cubre **solo los ámbitos disponibles al terminar US5**; el ámbito `recovery` lo prueba T137 en US7:

  | Ámbito | Ruta | Umbral |
  |---|---|---|
  | `login` | `POST /auth/login` | 20/min |
  | `mfa` | `POST /auth/login/mfa` | 10/min |
  | `register` | `POST /auth/register` | 5/hour |
  | `activation` | `POST /auth/activate` | 10/hour |
  | `mfa_reset_request` | `POST /auth/login/mfa-reset-request` | 3/day |

  Para cada ámbito, desde una IP simulada (`X-Forwarded-For` con `NUM_PROXIES = 1`) y con identificadores distintos para no activar los retrasos por cuenta:
  - las N primeras peticiones **no** devuelven 429;
  - la N+1 devuelve **429** con la cabecera **`Retry-After`** (entero positivo);
  - se registra **`throttle_ip_limited`** con `metadata.scope`;
  - otra IP no queda afectada;
  - el contador se reinicia al pasar la ventana (reloj simulado).
- [ ] T097 [P] [US5] Aceptación TS-A05 en `backend/tests/acceptance/test_us5_bruteforce.py`: una prueba por cada escenario 1–6 de US5

### Implementation for User Story 5

- [ ] T098 [P] [US5] Crear `AuthThrottle` y su migración en `backend/apps/iam/models/throttle.py` (data-model): `scope` enum `account`; `key_digest` char(64) (HMAC con **`THROTTLE_HMAC_KEYS`**, C1); `key_version` varchar(6); `consecutive_failures` int ("Se reinicia tras un éxito o tras 30 min sin fallos"); `last_failure_at`; `blocked_until` nulo ("30 s · 2^(n−5), con tope de 900 s, desde n = 5"); restricción única `(scope, key_digest)`
- [ ] T099 [US5] Implementar `backend/apps/iam/services/throttling.py` con `check(email)`, `register_failure(email, ip)` y `register_success(email)`. `check` consulta los resúmenes de **todas las versiones aceptadas** de `THROTTLE_HMAC_KEYS` y aplica el retraso más restrictivo; los fallos se registran en la versión activa, heredando el contador de la fila antigua (R12). Además: `select_for_update`, `throttle_digest()`, cálculo del retraso, eventos de anomalía y detección de relleno de credenciales (FR-036–FR-039)
- [ ] T100 [US5] Integrar la limitación en `backend/apps/iam/services/authentication.py`: llamar a `throttling.check` **antes** de evaluar credenciales en `password_login` y `complete_mfa` (TOTP y código de recuperación); un rechazo durante el retraso devuelve el 401 genérico; fallos y éxitos se registran en todos los caminos
- [ ] T101 [US5] Configurar los throttles de DRF en `backend/config/settings/base.py` y `backend/apps/iam/api/throttles.py`:
  - `DEFAULT_THROTTLE_RATES` con `login 20/min`, `mfa 10/min`, `register 5/hour`, `recovery 5/hour`, `activation 10/hour` y `mfa_reset_request 3/day`; `NUM_PROXIES = 1`.
  - Asignar `throttle_scope` en las vistas de US1, US3 y US4. El ámbito `recovery` se define aquí, pero lo asigna T114 (US7) y lo prueba T137.
  - Ante 429, `Retry-After` y evento `throttle_ip_limited`.
- [ ] T102 [P] [US5] Escribir `docs/security/throttling.md`: por qué retrasos progresivos y no bloqueo rígido, limitación por cuenta y por IP sin Redis, detección de anomalías y riesgo de NAT compartido (FR-049)

**Checkpoint**: US1–US5 funcionan de forma independiente.

---

## Phase 8: User Story 6 - Registro de eventos y consulta por el Auditor (Priority: P6)

**Goal**: el Auditor (con MFA) consulta y filtra los eventos de seguridad en modo de solo lectura;
el Administrador y el Cliente no tienen acceso.

**Independent Test**: se generan eventos con usuarios ficticios; el Auditor los filtra; el
Administrador recibe 403; los métodos de escritura dan 405. Escenarios V9 y V17 de quickstart.md.

### Tests for User Story 6 ⚠️

- [ ] T103 [P] [US6] Seguridad TS-S18 en `backend/tests/security/test_audit_access.py`: el Administrador y el Cliente sobre `/audit/events` y `/audit/event-types` dan 403; PUT, PATCH y DELETE dan 405; el Auditor sin MFA verificado no obtiene sesión `full`
- [ ] T104 [P] [US6] Contrato TS-C01 (parte US6) en `backend/tests/contract/test_audit_contract.py`: los filtros `from`, `to`, `event_type`, `outcome`, `actor_id` y `page`, los campos de cada evento y `GET /audit/event-types` con los 32 tipos
- [ ] T105 [P] [US6] Aceptación TS-A06 en `backend/tests/acceptance/test_us6_audit.py`: una prueba por cada escenario 1–4 de US6

### Implementation for User Story 6

- [ ] T106 [US6] Implementar `backend/apps/audit/permissions.py` (`IsAuditor` + `IsFullyAuthenticated`), `backend/apps/audit/serializers.py` y `backend/apps/audit/views.py` (rutas en `backend/apps/audit/urls.py`, montadas en `/api/v1/audit/`):
  - `GET /audit/events`: solo lectura, filtros, paginación y orden por `occurred_at` descendente.
  - `GET /audit/event-types`.
- [ ] T107 [P] [US6] Crear `frontend/src/pages/audit/Events.jsx`: filtros por fecha, tipo, resultado y usuario, paginación, sin acciones de edición
- [ ] T108 [P] [US6] Escribir `docs/security/audit.md` (FR-049):
  - Catálogo de eventos, metadatos con lista permitida y separación de funciones.
  - Las tres capas (modelo, triggers y rol `securefin_app`).
  - **Limitaciones**: el superusuario `postgres` y `securefin_owner` pueden saltarse los controles; no hay inmutabilidad absoluta (R14).

**Checkpoint**: US1–US6 funcionan de forma independiente.

---

## Phase 9: User Story 7 - Recuperación segura de contraseña (Priority: P7)

**Goal**: recuperación por el buzón de laboratorio con un token HMAC de un solo uso de **15
minutos**, respuesta idéntica exista o no la cuenta y revocación de todas las sesiones.

**Independent Test**: solicitud para una cuenta existente y para una inexistente (misma respuesta),
token desde Mailpit, restablecimiento, rechazo por reutilización o por caducidad de 15 min, y
sesiones previas revocadas. Escenario V14 de quickstart.md.

### Tests for User Story 7 ⚠️

- [ ] T109 [P] [US7] Seguridad TS-S09 en `backend/tests/security/test_enumeration_timing.py`: en 200 peticiones de `password-reset/request` (mitad existentes, mitad inexistentes), la diferencia media de tiempo es inferior a 100 ms **con el buzón disponible y con el SMTP detenido o simulado lento**; los cuerpos son idénticos (NFR-003)
- [ ] T110 [P] [US7] Seguridad TS-S08 en `backend/tests/security/test_tokens_not_logged.py`: tras el flujo completo de recuperación y activación, el token en claro no aparece en la base de datos (`iam_onetimetoken`, `iam_outboxmessage`), en los logs de Django capturados ni en los logs de acceso de Nginx (formato de T010)
- [ ] T111 [P] [US7] Contrato TS-C01 (parte US7) en `backend/tests/contract/test_recovery_contract.py`: `POST /auth/password-reset/request` (siempre `202 {"status": "if_account_exists_email_sent"}`) y `POST /auth/password-reset/confirm` (204 / `400 invalid_token`)
- [ ] T136 [P] [US7] E2E TS-E03 con Playwright en `frontend/tests/e2e/reset-form.spec.js` (FR-005, FR-048; correcciones I1 de la revisión 3, U1, U2 y U4). Solo prueba los formularios de US7, en las rutas exactas de `contracts/iam-api.md` §6. El token se obtiene del correo de recuperación con el *fixture* de T139, se consume en la prueba y el mensaje se borra al final, sin trazas, vídeos ni capturas:
  - `/forgot-password`: email con `autocomplete="username"` dentro de un `<form>` con botón `submit`.
  - `/reset#token=…`: contraseña nueva con `type="password"` y `autocomplete="new-password"`, pegado permitido, sin `autocomplete="off"` ni `readonly` y ningún `maxlength` inferior a 128.
  - Al cargar `/reset#token=…`, `location.hash` queda vacío **tras `history.replaceState`**; el envío consume el token (204) y un segundo uso falla (`400 invalid_token`).
- [ ] T137 [P] [US7] Seguridad TS-S28 (ámbito `recovery`) en `backend/tests/security/test_ip_rate_limit_recovery.py` (FR-037; corrección I2), junto con el endpoint de T114. Desde una IP simulada (`X-Forwarded-For`, `NUM_PROXIES = 1`), las 5 primeras peticiones de `POST /auth/password-reset/request` en una hora no devuelven 429, aunque mezclen identificadores existentes e inexistentes. La 6.ª devuelve **429** con **`Retry-After`** (entero positivo) y registra **`throttle_ip_limited`** con `metadata.scope = "recovery"`. Otra IP no queda afectada y el límite se reinicia al pasar la ventana (reloj simulado). Las respuestas anteriores al límite siguen siendo idénticas (FR-045).
- [ ] T112 [P] [US7] Aceptación TS-A07 en `backend/tests/acceptance/test_us7_recovery.py`: una prueba por cada escenario 1–5 de US7; el escenario 2 comprueba la caducidad de **15 minutos** con reloj simulado

### Implementation for User Story 7

- [ ] T113 [US7] Implementar `backend/apps/iam/services/password_reset.py` y registrar el *handler* `password_reset` del outbox (FR-045–FR-048):
  - `request_reset(email)` encola `password_reset` **solo** si la cuenta existe y está `active`, sin SMTP en la petición; evento `password_reset_requested`.
  - El *handler* ejecuta `tokens.issue(user, "password_reset")` (**15 min**, invalida los anteriores) con el enlace `https://securefin.local/reset#token=…`.
  - `confirm_reset(token, new_password)` aplica los validadores, cambia la contraseña y `password_changed_at`, marca el token como usado, ejecuta `revoke_all(user)` y conserva el `TOTPDevice`; eventos `password_reset_completed` y `password_changed`.
- [ ] T114 [US7] Implementar `backend/apps/iam/api/views/password_reset.py`: `POST /auth/password-reset/request` (siempre la misma respuesta 202) y `POST /auth/password-reset/confirm`, con `anonymous_state_changing` y `throttle_scope = "recovery"`; rutas en `backend/apps/iam/api/urls.py`
- [ ] T115 [P] [US7] Crear `frontend/src/pages/ForgotPassword.jsx` y `frontend/src/pages/Reset.jsx` (U1):
  - **Rutas exactas** (U4; `contracts/iam-api.md` §6): `/forgot-password` → `ForgotPassword`, que solicita la recuperación con `POST /auth/password-reset/request`; `/reset` (recibe `#token=…`) → `Reset`, que consume el token con `POST /auth/password-reset/confirm`. Se registran en `frontend/src/App.jsx`.
  - **`ForgotPassword`**: un `<form>` con botón `type="submit"` y email con `type="email"` y `autocomplete="username"`; siempre muestra el mismo mensaje neutro (FR-045).
  - **`Reset`**: usa `fragmentToken.js` (lectura en el primer render, `replaceState`, token solo en estado y descartado tras enviar); su formulario es un `<form>` con botón `type="submit"` y contraseña nueva con `type="password"` y `autocomplete="new-password"`.
  - Se permite pegar, sin `autocomplete="off"` ni `readonly` y sin ningún `maxlength` inferior a 128.
- [ ] T116 [P] [US7] Escribir `docs/security/recovery-and-mailbox.md` (FR-049): tokens HMAC versionados y caducidades (15 min recuperación, 24 h activación, 10 min código de reinicio de MFA), patrón outbox sin secretos, manejo del fragmento en React, y aislamiento de Mailpit (redes, doble autenticación, sin relay, retención y tratamiento de evidencias)

**Checkpoint**: las siete historias funcionan de forma independiente.

---

## Phase 10: Polish & Cross-Cutting Concerns

**Purpose**: verificaciones globales, rendimiento, evidencias y cierre de trazabilidad.

- [ ] T117 [P] Implementar el comando `backend/apps/iam/management/commands/iam_purge_expired.py`: elimina sesiones caducadas (`clear_expired`), tokens caducados o usados, altas TOTP `pending` de más de 10 min, casos `requested` de más de 24 h o `pending_verification` caducados (marcados como `expired`) y mensajes del outbox `sent` o `failed` de más de 24 h. **Purga controlada de `AuthThrottle`** (corrección G1; R12): borra una fila solo si `blocked_until` es nulo o ya pasó **y** además (a) `last_failure_at ≤ now − 30 min` o (b) su `key_version` ya no está entre las versiones aceptadas de `THROTTLE_HMAC_KEYS`. Nunca borra filas con un retraso vigente ni filas de una versión aceptada con fallos en los últimos 30 minutos. Informa de recuentos por categoría
- [ ] T138 [P] Integración TS-I19 en `backend/tests/integration/test_purge_expired.py` (corrección G1), con reloj simulado y `iam_purge_expired`:
  - **Se borran**: una fila de `AuthThrottle` de la versión activa con `last_failure_at` de hace 31 min y sin retraso; una fila de una versión retirada sin retraso vigente.
  - **Se conservan**: una fila con `blocked_until` en el futuro (de cualquier versión, incluida una retirada); una fila de la versión activa con un fallo hace 10 min; una fila de una versión aceptada no activa con un fallo reciente.
  - Tras la purga, una cuenta con retraso vigente sigue rechazando intentos sin evaluar credenciales.
  - Se verifican también las demás categorías de T117 (sesiones, tokens, altas `pending`, casos y outbox) y que los recuentos coinciden.
- [ ] T118 [P] Integración SC-006 en `backend/tests/integration/test_event_catalog_coverage.py`: tras ejecutar los flujos de todas las historias, los 32 tipos de `event_type` aparecen al menos una vez con todos los campos de FR-041
- [ ] T119 [P] Seguridad TS-S03/TS-S17 en `backend/tests/security/test_secrets_scan.py` (SC-003):
  - Se recogen todos los secretos emitidos durante la sesión de pruebas (contraseñas, tokens, códigos de recuperación y de verificación, secretos TOTP en base32 y valores de cookie).
  - Se buscan en un volcado de la base de datos, en `iam_outboxmessage`, en la `metadata` de `audit_securityevent`, en los logs capturados y en el SQL capturado.
  - Resultado esperado: 0 coincidencias.
- [ ] T120 [P] Seguridad TS-S10/TS-S11/TS-S25 en `backend/tests/security/test_infra_isolation.py` (marcador `stack`, se ejecuta en el trabajo `stack` de T014), analizando `docker compose config` en formato JSON:
  - Solo nginx publica puertos (`443`, `80` y `127.0.0.1:8025`).
  - `app_net`, `data_net` y `mail_net` tienen `internal: true`.
  - Mailpit solo está en `mail_net` y el backend no comparte red con Mailpit; Nginx no está en `data_net`.
  - No hay `MP_SMTP_RELAY_*`.
  - **TS-S11 en vivo**: `https://127.0.0.1:8025` y `https://127.0.0.1:8025/api/v1/messages` responden 401 sin credencial y 200 con `MAILPIT_API_USER` y `MAILPIT_API_PASSWORD`; `http://127.0.0.1:8025` (HTTP plano) no sirve contenido; el certificado se valida con la CA de laboratorio (SAN `IP:127.0.0.1`).
  - **Credenciales por servicio** (única ubicación de esta verificación; corrección D1): `db_owner_password` y `DB_USER=securefin_owner` solo están en `migrate`; `backend` y `mailer` usan `DB_USER=securefin_app`, montan solo `db_app_password` y no tienen acceso a `db_owner_password`.
- [ ] T121 [P] Seguridad TS-S19/TS-S21 en `backend/tests/security/test_edge_headers.py` (marcador `stack`, contra el stack de Compose levantado en el trabajo `stack` de T014; falla, no se omite, si no responde): CSP literal, HSTS, `X-Content-Type-Options`, `Referrer-Policy` y `no-store` en `index.html`; `openssl s_client -tls1_1` rechazado y TLS 1.2/1.3 aceptados
- [ ] T122 [P] Seguridad TS-S24 con Playwright en `frontend/tests/e2e/fragment-token.spec.js` (obligatorio; se ejecuta en el trabajo `stack` de T014):
  - Los tokens reales se obtienen con el *fixture* de Mailpit de T139 (U2).
  - Tras cargar `/reset#token=…` y `/activate#token=…`, `location.hash` está vacío **después de `history.replaceState`**, `history.length` no conserva una entrada con el fragmento y `localStorage`, `sessionStorage` e IndexedDB no contienen el token.
  - Al final se consume el token y se borran los mensajes.
  - Sin trazas, vídeos ni capturas; las aserciones no incluyen el valor del token en sus mensajes (U1).
- [ ] T123 Calibración de Argon2id TS-P02 en `docs/security/argon2-calibration.md`: ejecutar `python -m argon2 -t 3 -m 65536 -p 1 -n 100` y `/usr/bin/time -v` dentro de la imagen del backend; registrar la latencia media y el RSS máximo con fecha y equipo, y copiar los valores a la tabla de resultados de R4 en `specs/001-iam-access-control/research.md`
- [ ] T124 Rendimiento TS-P01 en `docs/security/argon2-calibration.md`:
  - Ejecutar `ab` sobre `POST /api/v1/auth/login` con concurrencias 1, 5, 10 y 20 y 20 cuentas ficticias distintas, registrando p50, p95, p99 y errores, más CPU y memoria con `docker stats`.
  - Si el p95 con concurrencia 20 es de 2 s o más, ajustar workers o recursos. **Bajar los parámetros de Argon2id requiere justificación escrita y aprobación del titular** (SC-010).
- [ ] T125 [P] Generar la evidencia manual:
  - Colección `docs/security/evidence/securefin-iam.postman_collection.json`, con CSRF automático y los escenarios V1–V18 de quickstart.md.
  - Salida de Nmap externo (TS-S10) en `docs/security/evidence/nmap.md`, con los tokens ocultos.
  - **Medición manual de SC-001** (escenario V0; corrección G4): 5 usuarios ficticios cronometran el registro y el primer inicio de sesión desde la página de registro hasta el área personal. Se anotan en `docs/security/evidence/sc-001.md` los tiempos individuales, la media, el criterio (todos por debajo de 2 minutos), la fecha y el equipo.
- [X] T126 Evaluar Django REST Framework 3.18.1 según los criterios de R17 (publicada en PyPI, matriz compatible con Django 5.2 y Python 3.13, `pip-compile` sin conflictos y suite completa en verde, incluidas TS-C y TS-SC):
  - Si los cumple, actualizar `backend/requirements.in` y recompilar `backend/requirements.txt`; si no, fijar la última 3.16.x.
  - Fijar Django en la última 5.2.x publicada.
  - Documentar versiones y decisión en `docs/security/dependencies.md`.
- [ ] T127 [P] Escribir `docs/security/README.md`: índice de los documentos por mecanismo (FR-049) y matriz de trazabilidad **FR-001…FR-050 y SC-001…SC-011 → ID de prueba** (SC-011), con referencias a `plan.md` → Test Strategy
- [ ] T130 [P] Escribir `docs/security/privacy.md` (Principio VII, Ley 1581 de 2012; corrección C4) con una tabla por dato que indique **finalidad**, **minimización**, **acceso** (roles y procesos), **retención** y **protección**:

  | Dato | Finalidad | Minimización | Acceso | Retención | Protección |
  |---|---|---|---|---|---|
  | Email | Identificación, login y canal de laboratorio | Ficticio `@lab.securefin.local` | Titular; Administrador (listado); Auditor (solo vía `actor_id`) | Vida de la cuenta en el laboratorio; se elimina al desmantelar el entorno | Normalizado; nunca en logs técnicos; en los eventos, solo el `actor_id` seudónimo |
  | Nombre | Mostrar la identidad | 1–100 caracteres, ficticio | Titular y Administrador | Igual que el email | No se registra en eventos |
  | Dirección IP | Mostrar las propias sesiones, limitación por IP e investigación de incidentes | Solo en `UserSession` y en eventos de autenticación, anomalía y administración (FR-041) | Titular (sus sesiones); Auditor (eventos) | En sesiones, hasta su borrado (≤ 8 h + purga); en eventos, con la retención de la auditoría | Red interna; no se expone a otros usuarios |
  | User-agent | Que el usuario reconozca sus sesiones | Truncado a 200 caracteres | Titular | Igual que la sesión | No se registra en eventos |
  | Identificadores de sesión | Autenticación | Solo su verificador HMAC en la base de datos; la cookie se emite solo al crear o rotar | Solo el motor de sesión | Hasta la expiración, revocación o purga | HMAC con `SESSION_HMAC_KEYS`; cookie `__Host-` `HttpOnly`/`Secure`/`SameSite=Strict` |
  | Eventos de seguridad | Trazabilidad e investigación (Principio VI) | Lista permitida de metadatos; sin secretos | Solo el Auditor (lectura) | Vigencia del laboratorio; eliminación al desmantelarlo con `securefin_owner` (R14) | Append-only frente a `securefin_app`; limitaciones documentadas |

  Incluye la declaración de que solo se usan identidades ficticias, la referencia a los principios de la Ley 1581 (finalidad, libertad, seguridad, confidencialidad y acceso) y un enlace desde `docs/security/README.md` (T127).
- [ ] T128 Ejecutar la validación completa de `specs/001-iam-access-control/quickstart.md` (§3–§9, V1–V18) sobre el stack de Compose y el pipeline de CI en verde (pytest con todos los marcadores, Semgrep, Bandit, pip-audit, npm audit y Trivy), con 0 hallazgos altos o críticos sin justificar

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: sin dependencias.
- **Foundational (Phase 2)**: depende de Setup y **bloquea todas las historias**. Dentro de la fase,
  T031 (`User`) va antes de cualquier migración; T033 → T034 → T035 (motor de sesión, verificado
  por T019–T021 y T134); T036 → T037 → T038 (auditoría; el motor de sesión emite `session_expired`
  con `record_event`, así que T037 va antes de cerrar T034); T042 y T043 → T044 (tokens y outbox).
- **Trabajo `stack` de la CI (T014)**: depende de T007, T008, T009, T010 y T011 (healthchecks) y
  ejecuta T120, T121, T122 y las E2E de cada historia: T133 (US1), T135 (US4) y T136 (US7). Cada
  E2E solo ejercita formularios de su propia historia. T139 (*fixture* de Mailpit, US4) va antes
  de T135, T136 y T122.
- **Pruebas por fase**: cada prueba de historia solo usa rutas ya creadas en esa historia o en las
  anteriores. T132 (US5) excluye `recovery`, que se prueba en T137 (US7). La verificación de
  credenciales por servicio está solo en T120 (marcador `stack`), no en T022.
- **Historias (Phase 3–9)**: dependen de Foundational y se hacen en orden de prioridad (P1 → P7) o
  en paralelo con varias personas.
- **Polish (Phase 10)**: depende de todas las historias.

### User Story Dependencies

| Historia | Depende de | Nota |
|---|---|---|
| US1 (P1) | Foundational | MVP. Ya impide sesiones `full` a roles con MFA obligatorio |
| US2 (P2) | Foundational | Usa usuarios precargados; la matriz T058 crece con US3–US7 |
| US3 (P3) | Foundational + `authentication.py` de US1 (T054) | Amplía el login con `pre_auth` |
| US4 (P4) | US3 | Los Administradores necesitan MFA; el reinicio actúa sobre `TOTPDevice` y `RecoveryCode`. Usa el outbox de Foundational |
| US5 (P5) | US1 (+ US3 para contar fallos de TOTP y códigos) | Se integra en `authentication.py` |
| US6 (P6) | Foundational (auditoría) | Los eventos de las demás historias enriquecen la prueba |
| US7 (P7) | Foundational (tokens y outbox) + US1 | Independiente de US3–US6 |

### Within Each User Story

- Las pruebas se escriben primero y deben fallar.
- Orden: modelos → servicios → vistas y rutas → frontend → documentación.
- Toda operación administrativa escribe su evento en la misma transacción.

### Parallel Opportunities

- Setup: T002, T006, T007, T008, T009, T012, T013 y T129.
- Foundational: todas las pruebas T015–T026 y T134 en paralelo; después, T027–T030, T032, T039 y
  T045 en paralelo.
- US1: las pruebas T046–T050, T131 y T133 en paralelo.
- US4: T082–T085 en paralelo; T139 (*fixture*) antes de T135.
- US5: T095–T097 y T132 en paralelo.
- US7: T109–T112, T136 y T137 en paralelo.
- Polish: T117–T122, T125, T127, T130 y T138 en paralelo.
- Cada historia: todas sus pruebas `[P]` juntas; los modelos, el frontend y la documentación `[P]`
  en paralelo con los servicios.
- US6 y US7 pueden avanzar en paralelo con US4 y US5 cuando haya capacidad.

---

## Parallel Example: User Story 3

```bash
# Pruebas de US3 en paralelo (deben fallar primero):
Task: "Pruebas unitarias TS-U03/U04 en backend/tests/unit/test_aead.py"
Task: "Integración TS-I09/TS-I10 en backend/tests/integration/test_mfa.py"
Task: "Seguridad TS-S15 en backend/tests/security/test_pre_auth.py"
Task: "Contrato US3 en backend/tests/contract/test_mfa_contract.py"
Task: "Aceptación TS-A03 en backend/tests/acceptance/test_us3_mfa.py"

# Implementación independiente en paralelo:
Task: "AES-256-GCM en backend/apps/iam/crypto/aead.py"
Task: "Modelos TOTPDevice y RecoveryCode en backend/apps/iam/models/mfa.py"
Task: "Páginas MfaStep, Enroll y RecoveryCodes en frontend/src/"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1: Setup.
2. Phase 2: Foundational, con especial cuidado en el motor de sesión (T019–T021, T033–T035).
3. Phase 3: US1.
4. **Parar y validar** con V1–V6 de quickstart.md y la suite de conformidad TS-SC.

### Incremental Delivery

1. Setup + Foundational → base lista.
2. US1 → MVP de autenticación.
3. US2 → control de acceso.
4. US3 → MFA (habilita los roles privilegiados).
5. US4 → administración y reinicio de MFA.
6. US5 → protección frente a fuerza bruta.
7. US6 → consulta de auditoría.
8. US7 → recuperación.
9. Polish → verificaciones globales, calibración, evidencias y trazabilidad.

### Parallel Team Strategy

Tras Foundational: persona A con US1 → US3 → US4; persona B con US2 → US6; persona C con US7 → US5.

---

## Notes

- `[P]` = archivos distintos y sin dependencias pendientes; `[USn]` = trazabilidad con spec.md.
- Hacer commit por tarea o por grupo lógico, con el pipeline en verde.
- No reducir los parámetros de Argon2id ni añadir dependencias sin justificación (Principio VIII).
- Cualquier desviación de un principio se registra en `plan.md` → Complexity Tracking antes de
  integrarse.
