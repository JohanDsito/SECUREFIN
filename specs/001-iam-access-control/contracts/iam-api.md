# Contrato de interfaces: Feature 001 — IAM

**Fecha**: 2026-11-08 (revisión 2) | **Plan**: [../plan.md](../plan.md) | **Modelo**: [../data-model.md](../data-model.md)

Contrato funcional de la API REST, de las rutas del frontend que reciben tokens, de los comandos de
consola y de los correos. Las pruebas de contrato (TS-C) verifican rutas, códigos, campos y
cabeceras, y la ausencia de campos sensibles.

## 1. Convenciones

- **Base**: `https://securefin.local/api/v1`, mismo origen que el frontend. Solo HTTPS.
- **Formato**: JSON UTF-8. Los campos desconocidos se rechazan con `400` (FR-002).
- **Autenticación**: cookie `__Host-sf_session` (`HttpOnly`, `Secure`, `SameSite=Strict`, sin
  `Expires`). Su valor nunca se persiste en el servidor (solo su verificador, R2).
- **Emisión de la cookie de sesión**: `Set-Cookie: __Host-sf_session` **solo** aparece en las
  respuestas que crean o rotan la sesión (login, elevación de `pre_auth` a `full`, confirmación de
  alta y cambios de MFA, que rotan la clave) y en las que la eliminan (logout, revocación de la
  propia sesión). Ninguna otra respuesta la reemite: la inactividad se renueva en el servidor
  (TS-SC15).
- **CSRF**: todo método no seguro exige `X-CSRFToken` (= cookie `__Host-sf_csrftoken`) y un
  `Origin` o `Referer` del mismo origen, también en los endpoints anónimos. Sin token → `403`.
- **CORS**: no hay cabeceras CORS.
- **Cabeceras globales de la API**: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
- **Errores**: `{"error": {"code": "<código>", "message": "<texto>"}}`.

| Estado | Uso |
|---|---|
| 400 | Validación (regla incumplida, sin detalles internos) |
| 401 | Sin sesión válida **o** fallo de autenticación. Cuerpo único: `{"code": "auth_failed", "message": "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."}` (FR-009) |
| 403 | Autenticado sin permiso de **función**, o sin CSRF |
| 404 | Recurso inexistente **o ajeno** (FR-017) |
| 409 | Conflicto de regla de negocio |
| 429 | Limitación por IP, con `Retry-After` |

**Columna "Acceso"**:

| Valor | Significado |
|---|---|
| Anon | Sin sesión |
| Pre | Sesión `pre_auth` |
| Full | Sesión completa con el MFA del rol cumplido |
| Owner | Además, `user_id` = usuario de la sesión (se acepta el alias `me`) |
| Roles | `C` Cliente, `A` Administrador, `Au` Auditor |

## 2. Autenticación y sesión (`/auth`)

| Método y ruta | Acceso | Cuerpo | Respuesta | FR |
|---|---|---|---|---|
| GET `/auth/csrf` | Anon | — | `204` + cookie CSRF | — |
| POST `/auth/register` | Anon · IP `register` | `{email, name, password}` | `201 {"status": "registered"}`; `400` validación o identificador no disponible (mensaje neutro) | FR-001–006 |
| POST `/auth/login` | Anon · IP `login` · cuenta | `{email, password}` | `200 {"status": "authenticated", "user": UserSummary}` \| `200 {"status": "mfa_required"}` \| `200 {"status": "mfa_enrollment_required"}`; `401` genérico. La clave de sesión **rota** al subir de nivel | FR-008, 009, 036 |
| POST `/auth/login/mfa` | Pre · IP `mfa` · cuenta | `{totp_code}` **o** `{recovery_code}` | `200 {"status": "authenticated", "user": UserSummary, "recovery_codes_remaining"?: n}`; `401` genérico | FR-008, 026, 029 |
| POST `/auth/login/enroll/setup` | Pre (alta obligatoria) | — | `200 {"otpauth_uri", "qr_svg_data_uri", "secret_base32"}` | FR-024, 025 |
| POST `/auth/login/enroll/confirm` | Pre (alta obligatoria) | `{totp_code}` | `200 {"status": "authenticated", "user": UserSummary, "recovery_codes": [10 × 28 caracteres]}` | FR-024, 028 |
| POST `/auth/login/mfa-reset-request` | Pre (MFA activo) · IP `mfa_reset_request` | — | `202 {"status": "mfa_reset_requested"}`; cierra la sesión `pre_auth`. Si ya hay un caso abierto, la misma respuesta (idempotente). Más de 3 en 24 h → `429` | FR-032, 034 (R11 paso 1) |
| POST `/auth/logout` | Pre/Full | — | `204`; elimina la fila de sesión | FR-010 |
| GET `/auth/session` | Full | — | `200 {"user": UserSummary, "session": {"public_id", "authenticated_at", "idle_expires_at", "absolute_expires_at"}}` | FR-011 |
| POST `/auth/activate` | Anon · IP `activation` | `{token, password}` | `204`; `400 {"code": "invalid_token"}` (mismo mensaje para usado, caducado, sustituido o alterado) | FR-021 |
| POST `/auth/password-reset/request` | Anon · IP `recovery` | `{email}` | **Siempre** `202 {"status": "if_account_exists_email_sent"}`; solo encola en el outbox | FR-045, 046 |
| POST `/auth/password-reset/confirm` | Anon · IP `recovery` | `{token, new_password}` | `204` (revoca todas las sesiones); `400 invalid_token` o de política | FR-048 |

`UserSummary` = `{id, email, name, role, mfa_enabled, mfa_required}`.

## 3. Recursos propios (`/users/{user_id}`)

Todas exigen **Full + Owner**. Un `user_id` ajeno → `404` y evento `authz_denied`.

| Método y ruta | Roles | Cuerpo | Respuesta | FR |
|---|---|---|---|---|
| GET `/users/{id}/profile` | C, A, Au | — | `200 {id, email, name, role, created_at}` | US2 |
| PATCH `/users/{id}/profile` | C, A, Au | `{name}` (cualquier otro campo → `400`) | `200` | FR-018 |
| GET `/users/{id}/sessions` | C, A, Au | — | `200 [{public_id, created_at, last_activity_at, ip_address, user_agent, current}]` | US2 |
| DELETE `/users/{id}/sessions/{public_id}` | C, A, Au | — | `204`; sesión ajena → `404` | FR-010 |
| GET `/users/{id}/security` | C, A, Au | — | `200 {mfa_enabled, mfa_required, recovery_codes_remaining}` | US2 |
| POST `/users/{id}/mfa/totp/setup` | C, A, Au | `{password}` si ya hay MFA activo | `200 {otpauth_uri, qr_svg_data_uri, secret_base32}` | FR-024, 031 |
| POST `/users/{id}/mfa/totp/confirm` | C, A, Au | `{totp_code}` | `200 {recovery_codes: [10]}`; revoca las demás sesiones y rota la actual | FR-024, 028, 031, 012 |
| POST `/users/{id}/mfa/totp/disable` | C | `{password, totp_code}` | `204`; `403` para A y Au | FR-027 |
| POST `/users/{id}/mfa/recovery-codes/regenerate` | C (con MFA), A, Au | `{password, totp_code}` | `200 {recovery_codes: [10]}` | FR-030 |

## 4. Administración (`/admin`; solo A + Full)

Otros roles → `403`. Evento en la misma transacción (FR-044).

| Método y ruta | Cuerpo | Respuesta | FR |
|---|---|---|---|
| GET `/admin/users?role=&status=&page=` | — | `200 {results: [{id, email, name, role, status, mfa_enabled, created_at, last_login_at}], next, previous}` | FR-019 |
| POST `/admin/users` | `{email, name, role}`, `role` ∈ {`admin`, `auditor`} | `201 {id, status: "pending_activation"}`; activación en el outbox | FR-019, 021 |
| POST `/admin/users/{id}/activation/resend` | — | `204` | FR-021 |
| PATCH `/admin/users/{id}/role` | `{role}` | `200`; revoca sesiones. Sobre sí mismo → `403`; último Administrador → `409` | FR-019, 020 |
| POST `/admin/users/{id}/deactivate` | — | `204`; revoca sesiones. Mismas reglas | FR-019, 020 |
| POST `/admin/users/{id}/reactivate` | — | `204` | FR-019 |
| GET `/admin/mfa-resets?status=requested` | — | `200 {results: [{case_id, target_user_id, target_email, requested_at, status}]}` | FR-032 |
| POST `/admin/mfa-resets/{case_id}/open` | `{request_channel}` (`in_person` \| `course_channel`) | `200 {status: "pending_verification"}`; desafío en el outbox. Titular = el propio Administrador → `403`; caso no `requested` → `409` | FR-032, 034 |
| POST `/admin/mfa-resets/{case_id}/authorize` | `{verification_code, admin_totp_code, channel_confirmed: true}` | `200 {status: "authorized"}`; código o TOTP inválido → `400 verification_failed` (al tercer intento, `cancelled`); caducado o ya resuelto → `409`; otro Administrador distinto del que abrió → `403` | FR-032–035 |
| POST `/admin/mfa-resets/{case_id}/cancel` | — | `204` | — |

## 5. Auditoría (`/audit`; solo Au + Full)

Administrador y Cliente → `403`. PUT, PATCH y DELETE → `405`.

| Método y ruta | Parámetros | Respuesta |
|---|---|---|
| GET `/audit/events` | `from`, `to`, `event_type`, `outcome`, `actor_id`, `page` | `200 {results: [{id, occurred_at, event_type, outcome, actor_id, actor_role, target_type, target_id, source_ip, request_id, metadata}], next, previous}` |
| GET `/audit/event-types` | — | `200 [31 tipos]` |

## 6. Rutas del frontend que reciben tokens

| Ruta | Fragmento | Contrato de comportamiento (R7) |
|---|---|---|
| `/forgot-password` | — (sin token) | Formulario que solicita la recuperación: email con `autocomplete="username"` → POST `/auth/password-reset/request` → siempre el mismo mensaje neutro (FR-045) |
| `/activate` | `#token=<43 caracteres base64url>` | Lee el token en el primer render → `history.replaceState` sin fragmento → token solo en memoria → POST `/auth/activate` → descarta el token |
| `/reset` | `#token=<43 caracteres base64url>` | Igual que `/activate`, con POST `/auth/password-reset/confirm` |

Estas tres rutas del frontend (`/forgot-password`, `/reset` y `/activate`) se usan **exactamente**
así en los correos (§8), en las páginas (T093, T115), en las pruebas E2E (T135, T136, T122) y en
quickstart.md (corrección U4). El endpoint REST de solicitud sigue siendo
`POST /auth/password-reset/request`.

Cabeceras de Nginx para el SPA: `Cache-Control: no-store` en `index.html`; `Referrer-Policy:
no-referrer`; CSP `default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:;
style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`.

## 7. Comandos de consola (solo en el entorno controlado; sin endpoint HTTP)

| Comando | Servicio | Precondición | Efecto | Salida |
|---|---|---|---|---|
| `migrate` | `migrate` (rol `securefin_owner`) | — | Esquema, permisos y triggers | Estándar de Django |
| `iam_bootstrap_admin --email E --name N` | backend | No existe ningún Administrador | Crea un Administrador en `pending_activation` y encola la activación; evento | Sin token; ≠ 0 si ya existe un Administrador |
| `iam_break_glass --email E --reason R` | backend | E es Administrador y no hay otro Administrador activo con MFA | Confirmación interactiva; efectos de FR-033; encola recuperación de contraseña; evento con el usuario del sistema operativo | Sin token |
| `iam_deliver_outbox [--once]` | mailer | — | Entrega los mensajes pendientes (genera el token o código al enviar) | Solo recuentos |
| `iam_rotate_totp_key --to vN` | backend | `vN` configurada | Recifra los `TOTPDevice` | Recuento |
| `iam_rotate_session_key --retire vN` | backend | `vN` no es la activa | Borra las sesiones `vN` y confirma la retirada | Recuento |
| `iam_purge_expired` | backend | — | Sesiones, tokens, altas, casos y mensajes del outbox caducados | Recuento |

## 8. Correos (solo al buzón de laboratorio, a través del outbox)

| `kind` | Contenido | Caducidad | Prohibido |
|---|---|---|---|
| `account_activation` | Enlace `https://securefin.local/activate#token=…` | 24 h | Contraseñas |
| `password_reset` | Enlace `https://securefin.local/reset#token=…` | 15 min (FR-046) | Indicar si hay MFA |
| `mfa_reset_challenge` | Código de 8 caracteres e instrucción de leerlo **solo** al Administrador por el canal registrado | 10 min | Enlaces |
| `mfa_reset_notice` | Fecha, aviso y qué hacer si no lo solicitó | — | Datos del Administrador más allá del rol |
