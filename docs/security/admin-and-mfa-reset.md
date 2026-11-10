# Administración de usuarios y reinicio de MFA

**Requisitos**: FR-012, FR-019 a FR-021, FR-032 a FR-035, FR-044, FR-049. **Decisiones**: research
R1, R9, R11, R15. **Código**: `backend/apps/iam/services/{admin_users,activation,mfa_reset}.py`,
`backend/apps/iam/models/mfa_reset.py`, `backend/apps/iam/api/views/{admin,activation,mfa}.py`,
`backend/apps/iam/api/serializers/admin.py`, `frontend/src/pages/{Activate,MfaStep}.jsx`,
`frontend/src/pages/admin/{Users,MfaResets}.jsx`. **Pruebas**: `tests/security/test_mfa_reset_abuse.py`
(TS-S12), `tests/integration/test_admin_services.py`, `tests/integration/test_admin_and_console.py`
(TS-I14/I17), `tests/contract/test_admin_contract.py` (TS-C01), `tests/acceptance/test_us4_admin.py`
(TS-A04), `tests/security/test_authz_matrix.py` (TS-S01) y `frontend/tests/e2e/activate-form.spec.js`
(TS-E02).

## Autorización de las rutas `/admin`

Cada petición pasa, en este orden, por:

1. **Sesión `full` con el MFA del rol cumplido** (`IsFullyAuthenticated`). Sin sesión o con una
   sesión `pre_auth` → `401`. Una sesión `full` cuya cuenta ya no está activa o cuyo rol exige un MFA
   que no tiene → denegada (`403`).
2. **Permiso de función** (`HasRolePermission`). Solo el rol Administrador tiene `admin.users.*` y
   `admin.mfa_reset`. Cliente y Auditor reciben `403` y se registra `authz_denied` (BFLA). La prueba
   generada de la matriz (T058) recorre automáticamente todas las rutas nuevas.
3. **Reglas de negocio en el servicio**, con los bloqueos tomados.

Los identificadores (`user_id`, `case_id`) llegan como texto y se validan en el servicio: mal formados
o inexistentes dan el mismo `404`. Las vistas no acceden al ORM (regla Semgrep
`securefin-views-use-services`).

| Regla | Respuesta | Evento |
|---|---|---|
| Autooperación: rol, desactivación, reactivación o reinicio del propio MFA | `403 self_action_forbidden` | `authz_denied` (`reason=self_action`) |
| Degradar o desactivar al último Administrador activo | `409 last_admin` | — |
| Transición no permitida (`active → deactivated → active`; reenviar activación solo a `pending_activation`) | `409 invalid_state` | — |
| Correo ya registrado al crear una cuenta | `409 user_exists` | — |
| Rol fuera de `{admin, auditor}` al crear, o campos desconocidos | `400 validation_error` | — |

## Integridad y concurrencia

- **Atomicidad (FR-044).** El cambio de estado, la revocación de sesiones (`sessions_revoked`) y el
  evento (`role_changed`, `account_deactivated`, `account_reactivated`, `account_created_by_admin`)
  se escriben en la misma `transaction.atomic`. Si `record_event` falla, todo se revierte (TS-I17).
- **Último Administrador.** `change_role` y `deactivate` bloquean con `SELECT … FOR UPDATE`, **en
  orden de id**, todas las filas de Administradores activos y después la del objetivo. Con los
  bloqueos tomados se comprueban, en este orden:
  1. que la operación no deja cero Administradores activos (`409`);
  2. que el actor sigue siendo Administrador activo, porque otra transacción pudo degradarlo
     mientras esperaba (`403`).

  El orden fijo de bloqueo evita interbloqueos. Si dos Administradores se degradan mutuamente a la
  vez, uno gana y el otro recibe `409` (`test_concurrent_mutual_demotion_keeps_one_admin`). Por la
  API, este `409` solo puede darse en una carrera así: cualquier actor válido es un Administrador
  activo distinto del objetivo.
- **Revocación (FR-012).** El cambio de rol, la desactivación y la reactivación revocan todas las
  sesiones del afectado (`pre_auth` y `full`). Tras pasar a Auditor o Administrador, el siguiente
  login exige el alta de MFA.

## Alta de cuentas privilegiadas y activación (FR-021)

1. `POST /admin/users` crea la cuenta en `pending_activation`, con contraseña inutilizable, y encola
   `account_activation` en el outbox, junto con `account_created_by_admin`, en la misma transacción.
   El Administrador nunca conoce ni fija la contraseña.
2. El mailer genera el token **en el momento de la entrega** (256 bits, solo se guarda su HMAC; un
   solo uso, válido 24 h contadas desde la entrega) y envía `https://securefin.local/activate#token=…`. Tras la entrega SMTP correcta
   registra `activation_sent`, sin el token.
3. `/activate` lee el fragmento al montar y lo elimina de la URL y del historial con
   `history.replaceState`. El token vive solo en el estado del componente y se descarta tras el
   envío. El formulario es compatible con gestores de contraseñas.
4. `POST /auth/activate` canjea el token y valida la política de contraseñas **en una única
   transacción**:
   - token usado, caducado, sustituido o alterado, o cuenta que ya no está pendiente → `400
     invalid_token`, siempre con el mismo mensaje;
   - contraseña que incumple la política → `400 validation_error`. El canje se revierte y el enlace
     sigue sirviendo.
5. La activación no crea sesión. En el primer login, Administrador y Auditor quedan en `pre_auth` con
   el alta de MFA obligatoria.

`POST /admin/users/{id}/activation/resend` encola un nuevo correo. El token anterior se invalida al
emitir el nuevo. El catálogo cerrado de eventos no tiene un tipo propio para el reenvío: la entrega
queda registrada con `activation_sent` o con `email_delivery_failed`.

## Reinicio administrativo de MFA: procedimiento de verificación (R11)

La identidad **no se acepta solo por conocer el nombre y el correo**. Se exigen tres elementos
verificables, más la reautenticación del Administrador:

| Elemento | Qué demuestra | Cómo lo comprueba el sistema |
|---|---|---|
| Contraseña | Conocimiento | La solicitud solo puede crearse desde una sesión `pre_auth` |
| Código al correo registrado | Posesión del buzón | Código de 8 caracteres (Crockford, 40 bits), solo su verificador Argon2id, 10 min |
| Canal fuera de banda | Contacto real con la persona | El Administrador registra el canal (`in_person` o `course_channel`) y confirma que recibió el código por él |
| Autorización | El Administrador actúa con su segundo factor | TOTP actual del Administrador (antirrepetición incluida) |

### Paso a paso

1. **Solicitud del titular.** Tras introducir su contraseña, en la pantalla del segundo factor el
   titular pulsa **"Perdí mi dispositivo y mis códigos"** (`POST /auth/login/mfa-reset-request`).
   - Requisitos: sesión `pre_auth` y MFA activo. Sin ellos, el mismo `401` genérico.
   - Se crea un caso `requested` (`request_verification = password`), se registra
     `mfa_reset_requested`, se revocan **todas** las sesiones del titular y se borra la cookie.
   - Es idempotente: si ya hay un caso abierto, devuelve la misma respuesta `202` sin crear otro.
   - Límite: 3 casos cada 24 h. El cuarto devuelve `429` con `Retry-After`.
2. **Contacto fuera de banda.** El Administrador contacta al titular por un canal oficial: en persona
   o por el canal oficial del curso. **No** usa el correo ni datos que el solicitante aporte en ese
   momento. Si no consigue el contacto, cancela el caso.
3. **Apertura.** En **Administración → Reinicios de MFA**, el Administrador abre el caso indicando el
   canal (`POST /admin/mfa-resets/{id}/open`).
   - Rechazos: el titular es él mismo (`403`); el caso no está `requested` (`409`); la cuenta del
     titular no está activa (`409`).
   - Efectos: estado `pending_verification`, se encola `mfa_reset_challenge` y se registra
     `mfa_reset_case_opened` con el canal.
4. **Desafío.** El mailer genera el código **al entregar**, guarda solo su verificador Argon2id
   (m = 19 MiB, t = 2, p = 1) con caducidad de 10 min desde la entrega, y lo envía sin enlaces al
   correo registrado. Si el caso ya no espera código (cancelado o caducado antes de la entrega), el
   código generado en memoria se descarta: no se guarda ningún verificador ni se envía el correo. El
   mensaje del outbox se reintenta y termina en `failed` con `email_delivery_failed`, sin código ni
   cuerpo (`test_challenge_not_sent_for_cancelled_case`).
5. **Lectura.** El titular lee el código al Administrador **por el canal registrado**.
6. **Autorización** (`POST /admin/mfa-resets/{id}/authorize`): código del titular, TOTP actual del
   Administrador y `channel_confirmed: true`. Se evalúan siempre los dos factores.
   - Solo puede autorizar quien abrió el caso. Otro Administrador recibe `403 not_case_owner` y no
     consume intentos.
   - Código o TOTP incorrectos → `400 verification_failed`. Al **tercer** fallo el caso pasa a
     `cancelled`, se borra el verificador y se registra `mfa_reset_cancelled` (`reason=max_attempts`).
   - Caso caducado o ya resuelto → `409`. Un código solo vale para su caso y una sola vez.
7. **Efectos**, en una única transacción:
   - se borra el `TOTPDevice` del titular y su lote vigente de códigos pasa a `invalidated` (los ya
     usados conservan `used`);
   - se revocan **todas** sus sesiones;
   - se borra el verificador;
   - se guarda `verification_method = password+email_challenge+out_of_band:<canal>`;
   - se registra `mfa_reset_authorized`: actor = autorizador, objetivo = titular (que es también el
     solicitante, `requested_by`), y metadatos con el método y las fechas de solicitud y apertura;
   - se encola `mfa_reset_notice`.
8. **Aviso** al titular: fecha del reinicio, que su contraseña no ha cambiado y qué hacer si no lo
   solicitó. No incluye datos del Administrador ni enlaces.

### Garantías (FR-035)

- El reinicio **no cambia la contraseña** ni crea sesión. El titular sigue necesitando su contraseña
  y, si su rol exige MFA, el siguiente login le obliga a darlo de alta de nuevo.
- El Administrador **nunca ve** el nuevo secreto ni los nuevos códigos (los genera el titular). Las
  respuestas y el listado no incluyen verificadores ni el código.
- El código del desafío no se guarda en claro ni aparece en eventos, logs ni outbox.
- **Caducidad perezosa**: un caso `requested` caduca a las 24 h sin abrir y uno `pending_verification`
  a los 10 min de la entrega. Se aplica antes de cualquier lectura o transición, en su propia
  transacción, para que un `409` posterior no la deshaga. Un caso caducado nunca bloquea una
  solicitud nueva.

### Concurrencia

- `request_reset` bloquea la fila del titular (`lock_user_mfa`): dos solicitudes simultáneas crean
  un único caso (`test_concurrent_reset_requests_create_one_case`). Además, la restricción única
  parcial impide dos casos abiertos por titular.
- `open_case`, `authorize` y `cancel` bloquean la fila del caso. `authorize` bloquea también al
  titular antes de borrar su dispositivo, igual que el resto de operaciones de MFA.

## Interfaz (T093)

| Página | Uso |
|---|---|
| `/admin/users` | Listado con filtros y paginación, alta de Administradores y Auditores, cambio de rol, desactivación, reactivación y reenvío de la activación |
| `/admin/mfa-resets` | Bandeja de casos por estado: abrir con el canal fuera de banda, autorizar (código del titular, TOTP propio y confirmación del canal) y cancelar |
| `/login/mfa` | Botón **"Perdí mi dispositivo y mis códigos"** en el segundo paso del login (`pre_auth`) |
| `/activate` | Activación con el token del fragmento; contraseña nueva compatible con gestores |

- **La interfaz no autoriza nada.** Los enlaces de administración solo se muestran al rol
  Administrador y la propia cuenta no ofrece acciones, pero es una comodidad: el servidor aplica
  todas las reglas y la interfaz se limita a mostrar sus respuestas (`401` con enlace para iniciar
  sesión, `403`, `409`, errores de validación por campo).
- **Confirmación explícita** antes de cambiar un rol, desactivar, reactivar, reenviar una
  activación, abrir o cancelar un caso y solicitar el reinicio propio. La confirmación es en línea
  (sin `window.confirm`) y recuerda las consecuencias: cierre de sesiones, código de 10 minutos,
  verificación fuera de banda.
- **Sin envíos dobles**: mientras hay una petición en curso, las demás acciones se deshabilitan y se
  muestra "Procesando…"; al cambiar filtros o de página se indica la carga.
- **Secretos**: el código del titular y el TOTP del Administrador solo existen en el formulario y se
  borran tras cada intento, haya éxito o error. Nada se guarda en `localStorage`, `sessionStorage`,
  cookies ni en la URL (regla Semgrep `securefin-no-web-storage` y pruebas E2E).
- **Pruebas**: `frontend/tests/e2e/admin-ui.spec.js` comprueba con la API simulada la carga, las
  confirmaciones, los envíos dobles, los errores y el almacenamiento. `activate-form.spec.js` (T135)
  recorre el flujo real: correo de Mailpit → `/activate` → login → alta de MFA. Necesita el stack.

## Riesgo abierto: límite de intentos

Hasta US5 (T095–T102, T132) **no hay retrasos progresivos por cuenta ni límites por IP** en
`/auth/login`, `/auth/login/mfa`, `/auth/activate` ni `/auth/login/mfa-reset-request`. El límite de 3
intentos por caso y de 3 casos cada 24 h solo cubre el reinicio. Mientras US5 no esté implementada,
SecureFin **no está listo para producción**: un atacante puede probar códigos TOTP del segundo paso
del login sin más freno que la ventana de 5 minutos de la sesión `pre_auth`.
