# Research: Feature 001 — Sistema de Identidad y Control de Acceso (IAM)

**Fecha**: 2026-11-08 (revisión 2) | **Plan**: [plan.md](./plan.md) | **Spec**: [spec.md](./spec.md)

Cada decisión sigue el formato exigido: alternativas, decisión, justificación, riesgos, mitigaciones
y verificación. Los identificadores `T-xx` remiten al análisis STRIDE de `plan.md`; los `TS-xx`, a
la estrategia de pruebas.

**Revisión 3** (corrección del análisis de coherencia): clave propia `THROTTLE_HMAC_KEYS` (R8, R12);
renovación de la inactividad en el servidor sin reemitir la cookie (R2, R13); credenciales de
PostgreSQL por servicio (R8, R14); CI por trabajos con stack de Compose y secretos efímeros (R16);
Playwright obligatorio (R17); pruebas de tiempos del login y de límites por IP (R9, R12).

**Revisión 2**: motor de sesión documentado por completo (R2); metodología de calibración de
Argon2id (R4); códigos de recuperación de 128 bits o más (R6); manejo del fragmento en React y
caducidades (R7); claves de sesión independientes (R8); patrón *outbox* (R9); segmentación de redes
(R10); identificación verificable del solicitante (R11); roles de PostgreSQL y límites de la
inmutabilidad (R14); versiones y bloqueo (R17).

---

## R1. Arquitectura del módulo IAM

- **Alternativas**: (a) una sola app Django con todo; (b) apps `core` + `iam` + `audit` dentro del
  monolito; (c) servicio de identidad separado (microservicio o proveedor externo).
- **Decisión**: (b). Monolito modular con tres apps Django:
  - `core`: reloj inyectable, identificador de petición, carga y validación de claves, filtro de
    redacción de logs.
  - `iam`: identidades, motor de sesión, MFA, tokens, limitación de intentos, administración,
    *outbox* de correo y comandos de consola. Organizada en `models/`, `services/`, `crypto/`,
    `sessions/`, `policies/`, `api/` y `management/commands/`.
  - `audit`: eventos append-only, servicio `record_event` y API del Auditor.
  Las vistas son delgadas: validan con serializers y delegan en servicios.
- **Justificación**: Principio VIII; separar `audit` permite permisos de base de datos propios (R14)
  y su reutilización.
- **Riesgos**: acoplamiento entre módulos; lógica de seguridad dispersa en vistas.
- **Mitigaciones**: `iam` solo usa la interfaz `audit.services.record_event`; regla de revisión
  "ninguna vista accede a modelos de seguridad sin pasar por un servicio".
- **Verificación**: pruebas unitarias de servicios; regla Semgrep propia que alerta sobre `objects.`
  en `iam/api/views`.

## R2. Mecanismo de sesión y motor de sesión propio

### R2.1 Cookies de sesión frente a tokens Bearer

| Criterio | (a) Sesión de servidor + cookie `HttpOnly` | (b) JWT Bearer en `localStorage` | (c) JWT de acceso en memoria + refresh en cookie |
|---|---|---|---|
| Robo por XSS | La cookie no es legible por JS | Exfiltrable | Exfiltrable mientras dura el token de acceso |
| Revocación inmediata (FR-010, FR-012) | Borrar la fila | Lista de revocación | Lista de revocación del refresh |
| Inactividad (FR-011) | En el servidor (`last_activity_at`), sin reemitir la cookie | Hay que construirla | Hay que construirla |
| CSRF | Necesario (R3) | No aplica | Necesario en el refresh |
| Complejidad Django + React | Baja | Media | Alta |
| Dependencias | Ninguna | simplejwt | simplejwt |

- **Decisión**: (a), sesión de servidor en PostgreSQL con cookie `__Host-sf_session` (`Secure`,
  `HttpOnly`, `SameSite=Strict`, `Path=/`, sin `Domain`), con el SPA React en el **mismo origen**.
  No se guarda nada sensible en `localStorage` ni `sessionStorage`.

### R2.2 Por qué hace falta un motor propio

El motor de base de datos de Django guarda el identificador (`session_key`) **en claro** como clave
primaria del modelo `Session`. La constitución (Principio III y Gobernanza) prohíbe sin excepción
guardar tokens en claro en la base de datos. Por eso el modelo `Session` predeterminado **no basta**
y se sustituye por un modelo propio con un motor que solo conoce verificadores.

### R2.3 Modelo `UserSession` (sin columna en claro)

| Campo | Tipo | Notas |
|---|---|---|
| `key_verifier` | `varchar(72)`, PK | `"<versión>$<hex64>"`; versión de 1 a 6 caracteres (`v1`…`v9999`) + `$` + 64 hex = 71 como máximo |
| `key_version` | `varchar(6)`, índice | Redundante con el prefijo; restricción `CHECK (key_verifier LIKE key_version \|\| '$%')` |
| `session_data` | text | Codificado y firmado por Django |
| `expire_date` | timestamptz, índice | **Caducidad absoluta**, nunca extendida, siempre calculada desde el `created_at` **inicial** (corrección I3; FR-011 "8 horas desde su creación"): `created_at + 5/10 min` en `pre_auth` y `created_at + 8 h` en `full` (y en cualquier otra fila). Al pasar de `pre_auth` a `full` se recalcula desde el **mismo** `created_at` |
| `public_id` | uuid, único | Identificador expuesto en la API (nunca el verificador) |
| `user_id` | FK, índice | **Propietario de la sesión, presente en `pre_auth` y en `full`** (corrección U3). Se desnormaliza al guardar desde `_sf_pending_user_id` (en `pre_auth`) o desde `_auth_user_id` de Django (en `full`). Solo sirve para correlacionar: revocación, expiración y `session_expired`. **No** autentica ni otorga permisos |
| `auth_level` | `varchar(10)` | `pre_auth` \| `full`. **No se persisten sesiones anónimas** (corrección I1) |
| `created_at` | timestamptz | **Creación inicial de la sesión** (normalmente en el paso `pre_auth`, o en el login directo de un Cliente sin MFA). **Base del límite absoluto de 8 h.** Se fija en la primera inserción y **se copia en cada rotación** (`cycle_key`): de `pre_auth` a `full`, login y cambios de MFA. Ninguna rotación lo reinicia |
| `authenticated_at` | timestamptz nulo | Momento en que la sesión pasó a `full`. Es informativo (se devuelve en `/auth/session`) y **no** interviene en la caducidad |
| `last_activity_at` | timestamptz | **Base de la inactividad de 15 min.** Se renueva en el servidor con un `UPDATE` directo de metadatos (granularidad de 60 s), sin tocar `session_data` y **sin reemitir la cookie** (C2) |
| `ip_address` / `user_agent` | inet / `varchar(200)` | Para que el usuario reconozca sus sesiones |

**Nacimiento de la sesión y CSRF (corrección I1)**:

- `CSRF_USE_SESSIONS = False`. La cookie `__Host-sf_csrftoken` es independiente del almacén de
  sesiones: pedir `GET /auth/csrf` **no crea** ninguna fila `UserSession` ni emite cookie de sesión.
- Las rutas anónimas que cambian estado siguen protegidas por CSRF (token de la cookie, cabecera
  `X-CSRFToken` y validación de origen), sin necesitar sesión.
- La **primera sesión de servidor** nace solo después de validar correctamente la contraseña:
  `pre_auth` si el usuario tiene MFA activo o su rol lo exige; `full` directamente si no hace falta
  MFA.
- El límite absoluto de 8 h empieza en el `created_at` de esa primera sesión y se hereda en todas
  las rotaciones.

**Usuario pendiente en `pre_auth` (corrección U3)**: `_sf_pending_user_id` es una clave interna de
los datos de sesión con el id del usuario cuya contraseña se validó pero que no ha completado el
MFA. No llama a `login()`, así que `request.user` sigue siendo `AnonymousUser`; no permite acceder a
endpoints protegidos (`IsFullyAuthenticated` exige `full`) ni otorga permisos. Solo correlaciona la
sesión con su propietario para la limitación de intentos, la expiración (`pre_auth_timeout`) y la
revocación. Al pasar a `full` se elimina y se sustituye por `_auth_user_id`.

**No existe ningún campo llamado `session_key`.** Si cualquier método heredado de Django no
sobrescrito intentara filtrar por `session_key=`, el ORM lanzaría `FieldError`, así que el diseño
**falla de forma cerrada** en lugar de consultar en claro. Además, `django.contrib.sessions` **no se
instala**, para que no se cree la tabla `django_session` y no haya ninguna caída accidental al
modelo por defecto.

### R2.4 Funcionamiento del motor (`iam.sessions.store.SessionStore`)

- **Base**: subclase de `django.contrib.sessions.backends.db.SessionStore` con `get_model_class()`
  → `UserSession`.
- **Claves**: `SESSION_HMAC_KEYS` (mapa versionado: una versión activa más las anteriores
  aceptadas), **independiente** de `DJANGO_SECRET_KEY`, `TOKEN_HMAC_KEYS`, `THROTTLE_HMAC_KEYS` y
  `TOTP_ENCRYPTION_KEYS`.
- **Ajustes** (decisión C2, alternativa B): `SESSION_SAVE_EVERY_REQUEST = False`,
  `SESSION_EXPIRE_AT_BROWSER_CLOSE = True` (cookie de sesión del navegador, sin `Expires`) y
  `SESSION_COOKIE_AGE = 28800`, usado solo como tope absoluto. La inactividad se controla en el
  servidor con `last_activity_at`.
- **Verificador**:
  `verifier(v, k) = v + "$" + hex(HMAC-SHA-256(SESSION_HMAC_KEYS[v], "securefin:session:" + k))`.

| Operación | Comportamiento |
|---|---|
| Generación (`_get_new_session_key`) | `secrets.token_urlsafe(32)` (256 bits, CSPRNG); se reintenta si `exists()` |
| Creación (`create`) | Bucle: clave nueva → `save(must_create=True)`; una `IntegrityError` provoca reintento. Inserta con el verificador de la **versión activa** |
| Guardado (`save`, `create_model_instance`) | **Solo ocurre cuando los datos de sesión cambian** (creación, login, elevación de nivel, cambios de MFA), porque `SESSION_SAVE_EVERY_REQUEST = False`. Construye la fila con `key_verifier`, datos, `expire_date` **absoluta** (calculada siempre desde el `created_at` inicial, nunca desde "ahora") y los metadatos (`user_id`, `auth_level`, `authenticated_at`). Si `must_create=False` usa `force_update` **sin** `update_or_create`: si la fila fue revocada entretanto, Django lanza `UpdateError` y la sesión **no se resucita** (el middleware responde `SessionInterrupted`) |
| Carga (`load`, `_get_session_from_db`) | Calcula el verificador para cada versión aceptada (activa primero) y busca `key_verifier = X` **sin** filtrar por fecha, para poder distinguir "caducada" de "inexistente". Si la fila existe pero `expire_date ≤ now` o `now − last_activity_at > 15 min`: la borra y, solo si tenía `user_id` (`pre_auth` o `full`), registra `session_expired` con el motivo `idle`, `absolute` o `pre_auth_timeout`. Si no la encuentra (cookie aleatoria, mal formada, de versión retirada o ya purgada), **no registra nada**. En ambos casos fija `self._session_key = None` y devuelve `{}`: **nunca adopta un identificador que no haya emitido** (anti-fijación) |
| Actividad (`touch`, desde `SessionLifetimeMiddleware`) | Si la sesión es válida y `now − last_activity_at ≥ 60 s`: `UserSession.objects.filter(key_verifier=X).update(last_activity_at=now, ip_address=…, user_agent=…)`. **No** marca la sesión como modificada, **no** cambia `session_data` ni `expire_date` y **no** provoca `Set-Cookie`. La granularidad de 60 s solo puede adelantar la caducidad, nunca superar los 15 min |
| Emisión de la cookie | `SessionMiddleware` solo envía `Set-Cookie: __Host-sf_session` cuando la sesión se crea o se modifica (creación con datos, `cycle_key` en login, elevación de `pre_auth` a `full` y cambios de MFA) y la borra en el logout o la revocación. Ninguna otra respuesta reemite el identificador |
| Existencia (`exists`) | Verificadores de todas las versiones aceptadas |
| Borrado (`delete`) | `DELETE` por verificadores; sin argumento, usa la clave actual |
| Rotación (`cycle_key`) | Comportamiento de Django (crear una nueva con los mismos datos y borrar la anterior). La fila nueva **hereda el `created_at` inicial** de la anterior, también en la elevación de `pre_auth` a `full`, en el login y tras los cambios de MFA, así que el límite absoluto no se reinicia nunca. `authenticated_at` se fija al pasar a `full` |
| Limpieza (`clear_expired`) | Borra si `expire_date < now` o si `created_at < now − 8 h` |
| API asíncrona de Django 5.x (`aload`, `asave`, `acreate`, `aexists`, `adelete`, `acycle_key`, `aclear_expired`) | Se sobrescriben y lanzan `NotImplementedError`: el proyecto es WSGI síncrono, y así no hay rutas heredadas sin revisar |

### R2.5 Integración con Django

| Pieza de Django | Interacción |
|---|---|
| `SessionMiddleware` | Carga mediante el motor; guarda y escribe la cookie **solo** cuando la sesión se modificó (`SESSION_SAVE_EVERY_REQUEST = False`). La clave en claro viaja únicamente hacia el navegador, en la creación o la rotación. Así se cumple que los tokens no aparezcan en respuestas posteriores a su emisión (Principio III) |
| `django.contrib.auth.login()` | Llama a `cycle_key()` (anti-fijación) y guarda `_auth_user_id`, `_auth_user_backend` y `_auth_user_hash` en los datos |
| `logout()` / `flush()` | Borra la fila y genera una clave nueva vacía |
| `update_session_auth_hash()` | No se usa: los cambios sensibles revocan con `revoke_all` (R13) |
| Hash de autenticación de sesión | Verifica `_auth_user_hash` contra el hash de la contraseña: defensa adicional |
| CSRF | `CSRF_USE_SESSIONS = False` (token en cookie); no interactúa con la clave |
| `clearsessions` | Funciona porque llama a `SessionStore.clear_expired()` |

**Operaciones que podrían filtrar la clave original y cómo se descartan**:

1. SQL de la aplicación: el modelo no tiene columna en claro.
2. SQL de Django: el motor solo emite verificadores.
3. Logs: la clave nunca se registra (filtro de redacción de cookies, `public_id` en la auditoría).
4. Código: una regla Semgrep restringe el acceso a `session.session_key` al motor y al middleware.
5. Postgres con `log_statement`: los parámetros son verificadores, no la clave.

### R2.6 Rotación e invalidación de la clave HMAC de sesión

- **Planificada**: añadir `v2` como activa; `v1` sigue aceptada como máximo 8 h (la duración
  absoluta máxima de una sesión). Después se retira `v1` con `iam_rotate_session_key --retire v1`,
  que ejecuta `DELETE … WHERE key_version = 'v1'`. Las sesiones `v1` no se migran: caducan solas.
- **De emergencia** (clave comprometida): retirar `v1` de inmediato y borrar todas sus sesiones. Todo
  el mundo vuelve a iniciar sesión.
- **Efecto real de un compromiso**: con identificadores aleatorios de 256 bits, conocer la clave HMAC
  **no permite** reconstruir identificadores a partir de la base de datos. El HMAC aporta
  cumplimiento constitucional y defensa en profundidad: impide verificar identificadores fuera del
  servidor.

### R2.7 Evaluación de garantías

Todas las propiedades exigidas se pueden garantizar con este diseño. Hay un riesgo residual: un
cambio de comportamiento interno de Django en una versión de mantenimiento 5.2.x. Se mitiga con:

- el modelo sin `session_key`, que falla de forma cerrada;
- la suite de conformidad TS-SC, obligatoria antes de cualquier actualización de Django;
- la versión fijada (R17).

Si algún día la suite no pudiera superarse, la alternativa que **no debilita** la constitución
sería un motor completo propio (sin heredar de `db.SessionStore`) que implemente la interfaz
`SessionBase`. Tiene más código pero ninguna dependencia de los internos del motor de base de datos.

- **Riesgos**: errores en el motor; carreras entre revocación y peticiones en curso; escritura en
  base de datos por cada petición.
- **Verificación**: suite de conformidad TS-SC01–SC20 (Test Strategy de `plan.md`).

## R3. CSRF y CORS acordes al mecanismo

- **Alternativas**: (a) CSRF de Django con mismo origen y sin CORS; (b) solo `SameSite`; (c) otro
  origen con `django-cors-headers`.
- **Decisión**: (a).
  - `CsrfViewMiddleware` y `SessionAuthentication` de DRF.
  - `csrf_protect` explícito en los endpoints anónimos que cambian estado (login, registro,
    recuperación, activación, pasos de MFA y solicitud de reinicio), para evitar el *login CSRF*.
  - `GET /api/v1/auth/csrf` entrega `__Host-sf_csrftoken`; el cliente la reenvía en `X-CSRFToken`.
  - `CSRF_TRUSTED_ORIGINS = ["https://securefin.local"]`.
  - **Sin cabeceras CORS** ni `django-cors-headers`.
  - Vite actúa como proxy en desarrollo para conservar el mismo origen.
- **Riesgos**: un endpoint anónimo nuevo sin `csrf_protect`; un CORS permisivo introducido en el
  futuro.
- **Mitigaciones**: prueba que recorre **todas** las rutas no seguras; regla Semgrep contra
  `csrf_exempt` y contra la instalación de CORS.
- **Verificación**: TS-S05, TS-S06, TS-S07.

## R4. Argon2id y política de contraseñas

- **Decisión de parámetros**: hasher Argon2id único (subclase de `Argon2PasswordHasher`) con
  **m=64 MiB (65536 KiB), t=3, p=1**, que se conservan inicialmente. **No se reducen por
  rendimiento** sin justificación escrita y aprobación del titular, y nunca por debajo del mínimo de
  OWASP (m=19 MiB, t=2, p=1).
- **Metodología de calibración** (en el equipo de laboratorio y con los resultados documentados):
  1. **Coste criptográfico aislado** con argon2-cffi:
     `python -m argon2 -t 3 -m 65536 -p 1 -n 100` dentro de la imagen del backend con sus límites de
     CPU y memoria. Registra la latencia media de hash y verificación.
     `/usr/bin/time -v` aporta el pico de memoria (RSS máximo) de un hash.
  2. **Carga real del endpoint** con Apache Benchmark sobre `POST /api/v1/auth/login` a
     concurrencias 1, 5, 10 y 20, con 20 cuentas ficticias distintas (para no activar los
     retrasos). Registra p50, p95, p99 y errores.
  3. **Recursos** durante la prueba 2 con `docker stats` (CPU % y memoria del contenedor). Pico de
     memoria esperado: aproximadamente workers × 64 MiB más la base.
  4. **Dimensionamiento**: el número de hashes simultáneos está acotado por los workers × hilos de
     gunicorn (inicialmente 4 × 1). Si no se cumple SC-010, se ajustan primero los workers y los
     recursos del contenedor; reducir parámetros exige aprobación.
- **Plantilla de resultados** (se completa en la implementación; hoy no hay mediciones):

  | Medición | Valor | Fecha / equipo |
  |---|---|---|
  | Hash aislado (media, ms) | Pendiente | |
  | Pico de memoria por hash (MiB) | Pendiente | |
  | Login p95 con concurrencia 20 (ms) | Pendiente | |
  | CPU y memoria máximas del contenedor | Pendiente | |

- **Política de contraseñas**:
  - Longitud de 15 a 128 caracteres (límite también en el serializer y en `client_max_body_size`).
  - `UserAttributeSimilarityValidator` y `CommonPasswordValidator`.
  - Lista de bloqueo local con términos del servicio y contraseñas comprometidas, con su fuente
    documentada.
  - Normalización Unicode NFKC en el registro y en el login.
  - Sin reglas de composición ni `NumericPasswordValidator`.
  - Sin consultas externas.
  - Se permite pegar y el autocompletado (`autocomplete="new-password"` o
    `"current-password"`).
- **Riesgos**: DoS por memoria; lista de bloqueo incompleta.
- **Mitigaciones**: throttles por IP, `limit_req` y tope de 128 caracteres; workers acotados.
- **Verificación**: TS-U01, TS-U02, TS-P01 (ab), TS-P02 (calibración aislada).

## R5. TOTP y cifrado de secretos

- **Alternativas**: `django-otp` (secreto en claro); RFC 6238 a mano (criptografía propia,
  prohibida); `pyotp` con modelo propio cifrado.
- **Decisión**: `pyotp` con el modelo `TOTPDevice`.
  - Secreto de 160 bits (`secrets`), SHA-1, 6 dígitos, periodo de 30 s y tolerancia de ±1.
  - Antirrepetición con `last_used_timestep` estrictamente creciente.
  - Cifrado AES-256-GCM (`cryptography`) con `TOTP_ENCRYPTION_KEYS[v]`, nonce aleatorio de 96 bits
    y AAD `"securefin:totp:v1:" + user.id`.
  - El alta `pending` caduca a los 10 minutos.
  - QR con `segno` como `data:image/svg+xml;base64` mostrado en `<img>`.
  - Secreto devuelto una sola vez con `no-store`.
- **Riesgos**: reutilización de nonce; pérdida de la clave; exposición durante el alta.
- **Mitigaciones**: nonce aleatorio por operación; claves versionadas y `iam_rotate_totp_key`;
  alta solo con sesión válida.
- **Verificación**: TS-U03, TS-U04, TS-I09, TS-S03.

## R6. Códigos de recuperación de MFA (128 bits o más)

- **Discrepancia resuelta**: la revisión 1 usaba 80 bits (por encima del mínimo constitucional de
  64). Se adopta la instrucción del titular: **al menos 128 bits por código**. No hay impedimento
  técnico.
- **Decisión**:
  - **Generación**: 10 códigos por lote; cada uno, 28 caracteres de `secrets.choice` sobre el
    alfabeto base32 de Crockford (32 símbolos): **140 bits** por código.
  - **Formato**: siete grupos de cuatro (`7K2M-9QXD-4HTR-B8NW-ZC3F-1VJE-6PAS`). El alfabeto evita
    caracteres ambiguos (sin I, L, O ni U).
  - **Usabilidad**: se muestran una sola vez con opción de copiar y descargar como `.txt`, que
    genera el propio navegador sin pasar por el servidor. La entrada acepta minúsculas, espacios y
    guiones, y mapea `I`/`L`→`1` y `O`→`0`. Se puede pegar.
  - **Almacenamiento**: verificador Argon2id (argon2-cffi) por código, con **m=19 MiB, t=2, p=1**
    (mínimo de OWASP). Con 140 bits de entropía, un ataque fuera de línea ya es inviable; el coste
    reducido mantiene el peor caso de verificación (10 códigos) por debajo de aproximadamente
    0,5 s. La constitución exige Argon2id para estos códigos, así que **no** se añade un índice HMAC
    (sería un verificador rápido adicional).
  - **Intentos repetidos**: solo se puede probar un código desde una sesión `pre_auth` (contraseña
    ya verificada). Cada fallo cuenta en la limitación por cuenta (R12) y en el throttle `mfa` por
    IP.
  - **Uso único**: la verificación y el marcado como `used` ocurren en una transacción con
    `select_for_update` sobre los códigos del usuario, para que dos peticiones concurrentes no
    consuman el mismo código.
  - **Regenerar o reconfigurar** invalida el lote anterior (`batch_id`).
- **Riesgos**: códigos largos (fricción); coste de verificación.
- **Mitigaciones**: copiar y pegar, formato agrupado y normalización; uso poco frecuente; limitación
  de intentos.
- **Verificación**: TS-U05 (longitud 28, alfabeto, al menos 128 bits y unicidad en 10⁵ muestras),
  TS-I10 (uso único, lote anterior rechazado, concurrencia), TS-S03.

## R7. Tokens de un solo uso (HMAC-SHA-256) y manejo en el navegador

- **Alternativas**: tokens sin estado de Django (no garantizan un solo uso ni la sustitución);
  SHA-256 sin clave (prohibido); HMAC-SHA-256 con clave dedicada.
- **Decisión** (modelo `OneTimeToken`):
  - Token de `secrets.token_urlsafe(32)` (256 bits).
  - Verificador `HMAC-SHA-256(TOKEN_HMAC_KEYS[v], propósito + ":" + token)` con índice único y
    `key_version`.
  - Búsqueda por verificador y comparación con `hmac.compare_digest`.
  - Canje en una transacción con `select_for_update`.
- **Caducidades (separadas)**:

  | Elemento | Caducidad | Observación |
  |---|---|---|
  | Activación de cuenta | 24 h | Coincide con FR-021 |
  | Recuperación de contraseña | **15 min** | Coincide con FR-046 y el escenario 2 de US7 (decisión confirmada por el titular el 2026-11-09). Cuenta desde la emisión del token, que ocurre en la entrega del outbox (R9) |
  | Código de verificación del reinicio de MFA | 10 min | No es un token HMAC: es un código de 8 caracteres con verificador Argon2id (R11) |

- **Manejo en React** de los enlaces `https://securefin.local/reset#token=…` y `/activate#token=…`:
  1. Al montar la página, el token se lee de `window.location.hash` **en el primer render**.
  2. Inmediatamente se ejecuta
     `history.replaceState(null, "", location.pathname + location.search)`, que elimina el
     fragmento de la entrada del historial.
  3. El token vive solo en el estado del componente (memoria); **nunca** en `localStorage`,
     `sessionStorage`, IndexedDB, cookies, la URL o el estado del router.
  4. Se descarta del estado al enviar el formulario o al desmontar.
  5. No hay scripts de terceros, analítica ni telemetría. La CSP (`script-src 'self'`,
     `connect-src 'self'`) lo impide, y los manejadores de error no incluyen la URL ni el estado.
  6. Las cabeceras `Referrer-Policy: no-referrer` y `Cache-Control: no-store` se aplican a
     `index.html`, `/reset` y `/activate` y a las respuestas de la API.
  7. El fragmento nunca llega al servidor ni a los logs de Nginx.
- **Riesgos**: token en el historial del navegador o en extensiones; tokens en los logs.
- **Mitigaciones**: `replaceState`, vida corta y un solo uso; filtro de redacción.
- **Verificación**: TS-U06, TS-I11, TS-S08, TS-S24 (prueba de navegador: tras cargar `/reset#token=…`,
  `location.hash` está vacío y el almacenamiento del navegador no contiene el token).

## R8. Gestión de claves

- **Decisión**: secretos de Docker Compose (archivos en `secrets/`, ignorados por git, generados con
  `openssl rand -base64 32`).

| Clave | Uso | Versionado |
|---|---|---|
| `DJANGO_SECRET_KEY` | Firma de Django (datos de sesión, CSRF) | — |
| `SESSION_HMAC_KEYS` | Verificadores de sesión (R2) | Sí |
| `TOKEN_HMAC_KEYS` | **Solo** verificadores de tokens de un solo uso (R7) | Sí |
| `THROTTLE_HMAC_KEYS` | **Solo** resúmenes seudonimizados de las claves de limitación por cuenta (R12) | Sí |
| `TOTP_ENCRYPTION_KEYS` | AES-256-GCM de los secretos TOTP (R5) | Sí |
| Contraseñas de los roles de PostgreSQL | `db_owner_password` (solo el servicio `migrate`) y `db_app_password` (backend y mailer) | — |

- **Una clave por propósito criptográfico** (corrección C1): ninguna clave HMAC se comparte entre
  sesiones, tokens y limitación. Así se cumple la "clave independiente, dedicada a este fin" del
  Principio III.
- `core.keys` valida al arrancar: presencia, al menos 32 bytes por versión y **todas las claves
  distintas entre sí**, incluidas todas las versiones de los cinco conjuntos. Si algo falla, no
  arranca.
- **Credenciales de PostgreSQL por servicio** (corrección U1): la configuración lee `DB_USER` y
  `DB_PASSWORD_FILE` del entorno de cada servicio. `backend` y `mailer` reciben `securefin_app` y
  `/run/secrets/db_app_password`; solo `migrate` recibe `securefin_owner` y
  `/run/secrets/db_owner_password`. Una comprobación al arrancar (`SECUREFIN_PROCESS_ROLE` igual a
  `runtime` o `migrate`) impide que un proceso de ejecución arranque conectado como
  `securefin_owner`.
- **Rotación y pérdida**:

  | Clave | Rotación planificada | Pérdida o compromiso |
  |---|---|---|
  | Sesión | R2.6 | Se cierran todas las sesiones |
  | Tokens | `v2` activa; `v1` aceptada hasta 24 h | Se invalidan los tokens pendientes |
  | Limitación | `v2` activa para los resúmenes nuevos; `v1` sigue aceptada para consultar retrasos vigentes y sus filas se purgan según la regla de R12 (sin retraso vigente y 30 min sin fallos); después se retira `v1` | Se reinician los contadores de retraso por cuenta (ventana de reintento de, como máximo, 5 intentos). Se documenta como riesgo aceptado |
  | TOTP | `iam_rotate_totp_key --to v2` | Todos vuelven a dar de alta su MFA (*break-glass* para el último Administrador) |

- **Verificación**: TS-U07; escaneo de secretos en CI.

## R9. Recuperación, activación y enumeración temporal: patrón *outbox*

- **Problema**: con envío síncrono, la respuesta para una cuenta existente incluye el diálogo SMTP,
  ausente para una inexistente. Si Mailpit va lento o está caído, la diferencia llega al *timeout*
  (3 s): **oráculo de enumeración** significativo. No se usarán hilos improvisados.
- **Alternativas**:
  - (a) Síncrono con trabajo equivalente: no cubre un Mailpit lento.
  - (b) Hilo tras la respuesta: descartado por el titular; además, se pierden mensajes si el worker
    muere.
  - (c) Cola con Redis/Celery: Redis no se añade por defecto.
  - (d) **Outbox en PostgreSQL con un proceso de entrega controlado**.
- **Decisión**: (d), sin guardar secretos.
  - La petición solo inserta un `OutboxMessage` con `kind`, `user_id`, `related_id` y `status`.
    **No** contiene token, código ni cuerpo del correo.
  - Para un identificador inexistente no se inserta nada. La diferencia es un INSERT indexado (del
    orden de milisegundos), muy por debajo de 100 ms y que no depende de Mailpit.
  - El proceso `mailer` (mismo contenedor de imagen, comando `iam_deliver_outbox`) recoge mensajes
    con `select_for_update(skip_locked=True)`.
  - **El token o código se genera en el momento de la entrega**: se crea el `OneTimeToken` (solo el
    HMAC) o el verificador Argon2id del caso, se compone el correo en memoria, se envía a Mailpit y
    se marca como `sent`. La caducidad cuenta desde la entrega.
  - Reintentos con espera exponencial: hasta 5 en unos 15 minutos. Después, `failed` y evento
    `email_delivery_failed` (sin secretos).
  - Retención: filas `sent` y `failed` eliminadas a las 24 h por `iam_purge_expired`.
  - Un mensaje nuevo del mismo tipo y usuario invalida al generarse los tokens anteriores (FR-046);
    solo el último enlace es válido.
  - Activación, desafío y notificación de reinicio de MFA usan el mismo outbox.
- **Coste de complejidad**: una tabla, un comando y un servicio de Compose sin puertos. Se justifica
  porque elimina el oráculo dependiente de Mailpit, aporta resiliencia ante caídas del buzón y
  **no** requiere Redis.
- **Limitación residual aceptada**: la diferencia de un INSERT entre cuentas existentes e
  inexistentes (medible pero inferior a 100 ms; TS-S09 la verifica en cada CI). También queda el
  retraso de entrega (de segundos) visible para el usuario.
- **Flujos**:
  - **Recuperación**: `request` → siempre `202` (outbox si la cuenta existe y está activa).
    `confirm` → valida el token y la política, cambia la contraseña, marca el token como usado,
    revoca todas las sesiones y conserva el MFA.
  - **Activación**: el Administrador crea la cuenta en `pending_activation` → outbox → token de 24 h
    → `POST /auth/activate`.
- **Verificación**: TS-S27 (**login**: usuario existente con contraseña errónea frente a usuario
  inexistente; mismo estado, cuerpo y conjunto de cabeceras, y Δ medio < 100 ms en 200 peticiones;
  corrección G1), TS-S09 (recuperación: Δ medio < 100 ms en 200 peticiones, con Mailpit activo **y
  detenido**),
  TS-I12 (Mailpit caído: `202`, reintentos y evento final), TS-I18 (el outbox no contiene
  secretos), TS-A07.

## R10. Integración y aislamiento de Mailpit; segmentación de redes

- **Redes de Docker Compose**:

  | Red | Tipo | Miembros | Propósito |
  |---|---|---|---|
  | `edge_net` | bridge | nginx | Publica `443`, `80` y `127.0.0.1:8025` |
  | `app_net` | `internal: true` | nginx, backend | Proxy de `/api` |
  | `data_net` | `internal: true` | backend, mailer, migrate, db | PostgreSQL |
  | `mail_net` | `internal: true` | mailer, mailpit, nginx | SMTP (mailer) e interfaz (nginx) |

  Nginx no está en `data_net` (no alcanza la base de datos). Mailpit no está en ninguna red con
  salida. El backend web **no** comparte red con Mailpit: solo encola en el outbox, y el proceso
  Django que envía (`mailer`) comparte con Mailpit únicamente `mail_net`.

- **Mailpit**:
  - Imagen con versión y *digest* fijados.
  - **Sin puertos publicados**: ni SMTP 1025 ni interfaz 8025.
  - Su interfaz y su API REST solo se consultan a través de un `server` de Nginx publicado **solo**
    en `127.0.0.1:8025`, **con TLS** (`https://127.0.0.1:8025`, certificado de la CA de laboratorio
    con SAN `IP:127.0.0.1`). La revisión 4 lo dejaba en HTTP, pero las credenciales Basic y los
    tokens de los mensajes cruzarían así el límite de confianza host ↔ contenedores (Principio III).
  - **Doble autenticación con una sola credencial**: una petición solo lleva una cabecera
    `Authorization: Basic`, que Nginx valida contra su `htpasswd` y reenvía a Mailpit, que la vuelve
    a validar contra su `MP_UI_AUTH_FILE`. Ambos archivos contienen **la misma** credencial. Así es
    defensa en profundidad ante un fallo de configuración de una de las capas, no dos credenciales
    distintas. La autenticación de Mailpit protege tanto la interfaz como la API.
  - Sin `MP_SMTP_RELAY_*`, así que no hay relay ni "liberación" de mensajes.
  - Retención de 200 mensajes y 24 h.
  - Bloqueo de recursos remotos en la vista HTML.
- **Django (proceso `mailer`)**: `EmailBackend` SMTP hacia `mailpit:1025` sin TLS (**excepción
  E3** en Complexity Tracking). El backend `locmem` se usa en las pruebas.
- **Evidencias**: con los tokens ocultos o usando tokens ya consumidos o caducados.
- **Fixtures automatizados de Mailpit (corrección U2)**:
  - Los *fixtures* E2E y `stack` obtienen los mensajes **solo** con la API REST autenticada de
    Mailpit, a través de Nginx en `https://127.0.0.1:8025`: `GET /api/v1/messages` para localizar el
    mensaje (por destinatario y asunto) y `GET /api/v1/message/{ID}` o `/api/v1/message/{ID}/raw`
    para leer su contenido.
  - Autenticación Basic con `MAILPIT_API_USER` y `MAILPIT_API_PASSWORD`, variables de entorno
    efímeras generadas en el trabajo de CI. Se confía en la CA de laboratorio efímera.
  - El token o código se extrae **solo en memoria** y nunca se imprime, se escribe en archivos ni se
    adjunta a informes.
  - Al terminar, el *fixture* borra los mensajes de prueba (`DELETE /api/v1/messages` con sus IDs).
  - Mailpit sigue sin ser accesible desde redes externas.
- **Verificación**: TS-S10 (`docker compose config` y Nmap externo), TS-S11 (doble autenticación),
  TS-I13 (entrega solo en el buzón), TS-S25 (inventario de redes: Mailpit solo en `mail_net`;
  backend y Mailpit solo comparten `mail_net`; ninguna red de Mailpit sin `internal: true`).

## R11. Reinicio administrativo de MFA y verificación de identidad

**Principio**: la identidad del solicitante no se acepta solo por conocer su nombre y su correo. Se
exigen tres elementos verificables por el sistema, más la autorización reforzada del Administrador:

| Elemento | Qué demuestra | Cómo se verifica |
|---|---|---|
| 1. Contraseña | Conocimiento | La solicitud solo puede crearse desde una sesión `pre_auth`, es decir, tras validar la contraseña |
| 2. Código al correo registrado | Posesión del buzón | Código de 8 caracteres enviado al correo registrado y leído por el usuario al Administrador |
| 3. Canal fuera de banda | Contacto con la persona | El Administrador registra el canal (presencial o canal oficial del curso) por el que recibe el código |
| Autorización | El Administrador actúa con su propio segundo factor | TOTP actual del Administrador |

**Procedimiento**:

1. **Solicitud verificada (titular)**: tras introducir su contraseña (sesión `pre_auth`), el titular
   elige "perdí mi dispositivo y mis códigos" (`POST /auth/login/mfa-reset-request`). Se crea un
   `MfaResetCase` en estado `requested`, con `requested_by = titular` y
   `request_verification = password`, y se registra `mfa_reset_requested`. La sesión `pre_auth` se
   cierra. Límites: un caso abierto por usuario y 3 solicitudes cada 24 h.
2. **Apertura (Administrador)**: un Administrador con MFA activo, distinto del titular, abre el caso
   (`POST /admin/mfa-resets/{id}/open`) indicando el canal fuera de banda. El outbox genera en el
   momento de la entrega un **código de 8 caracteres** (`secrets.choice` sobre base32 de Crockford,
   40 bits). Guarda solo su verificador Argon2id (m=19 MiB, t=2, p=1) con caducidad de **10
   minutos** y lo envía al correo registrado. Estado: `pending_verification`.
3. **Comprobación fuera de banda**: el titular lee el código al Administrador por el canal
   registrado.
4. **Autorización con reautenticación**: `POST /admin/mfa-resets/{id}/authorize` con el código, el
   TOTP actual del Administrador y la confirmación del canal. Se rechaza si:
   - el Administrador no tiene MFA activo, es el titular (**autorreinicio prohibido**) o no es quien
     abrió el caso;
   - el código es incorrecto (**máximo 3 intentos**; al tercero, `cancelled` y evento);
   - el caso caducó;
   - el código ya se usó (**antirreutilización**: el verificador se borra al autorizar o cancelar,
     y un código solo vale para su caso).
5. **Efectos** (FR-033 a FR-035), en una única transacción junto con el evento:
   - invalida el secreto TOTP y todos los códigos de recuperación;
   - **revoca todas las sesiones**;
   - deja el alta de MFA obligatoria si el rol la exige;
   - registra `mfa_reset_authorized` con solicitante, autorizador, fechas (solicitud, apertura y
     autorización) y método `password+email_challenge+out_of_band:<canal>`;
   - encola la **notificación** al titular.
6. **Garantías**: el reinicio **no modifica la contraseña** ni concede una sesión. El Administrador
   **nunca** ve el nuevo secreto TOTP ni los nuevos códigos, porque los crea el titular en su
   siguiente login.
7. Si el titular también perdió la contraseña, primero recupera la contraseña por correo (R9) y
   después solicita el reinicio.

**Primer y último Administrador (consola)**:

- `iam_bootstrap_admin --email --name`: solo si no existe ningún Administrador. Crea la cuenta en
  `pending_activation` y encola la activación. Sin contraseñas por argumentos y sin imprimir tokens.
- `iam_break_glass --email --reason`: solo si no hay **otro** Administrador activo con MFA. Pide
  confirmación interactiva, aplica los efectos del paso 5, encola un token de recuperación de
  contraseña y registra `break_glass_executed` con el usuario del sistema operativo.

- **Alternativas**: solo nombre y correo (insuficiente, rechazado por el titular); solo el desafío
  por correo (no demuestra conocimiento); doble aprobación de Administradores (mejora futura).
- **Riesgos**: un atacante con la contraseña y el buzón de la víctima; un Administrador malicioso.
- **Mitigaciones**: con contraseña y buzón, el atacante ya podría restablecer la contraseña (riesgo
  inherente a la recuperación por correo); notificación al titular; evento inmutable para el Auditor.
- **Verificación**: TS-A04, TS-S12 (autorreinicio, sin TOTP, código caducado, cuarto intento,
  reutilización, solicitud sin `pre_auth`), TS-I14.

## R12. Protección progresiva ante intentos fallidos (sin Redis)

- **Alternativas**: `django-axes` (bloqueo rígido); solo Nginx; Redis; PostgreSQL.
- **Decisión**:
  - **Por cuenta**: modelo `AuthThrottle` con la clave `HMAC(THROTTLE_HMAC_KEYS[v], "throttle:acct:"
    + email normalizado)` y `key_version`. La clave es exclusiva de este fin (C1). Durante una rotación, `check()` consulta los resúmenes de
    **todas las versiones aceptadas** y aplica el retraso más restrictivo. Los fallos nuevos se
    registran en la versión activa, heredando el contador de la fila antigua, que se borra al
    migrar, para que una rotación no elimine un bloqueo vigente.
  - **Purga controlada** (`iam_purge_expired`; corrección G1): borra una fila de `AuthThrottle` solo
    si `blocked_until` es nulo o ya pasó **y** además (a) `last_failure_at ≤ now − 30 min` o (b) su
    `key_version` ya no está entre las versiones aceptadas. **Nunca** borra una fila con un retraso
    vigente ni una con fallos en los últimos 30 minutos de una versión aceptada. Desde el 5.º fallo, retrasos de 30, 60, 120, 240 y 480 s, y después 900 s
    como tope. Durante el retraso, rechazo sin evaluar credenciales con el 401 genérico. Se reinicia
    tras un éxito o tras 30 min sin fallos. Actualizaciones con `select_for_update`.
  - **Por IP**: throttles de DRF por ámbito con `DatabaseCache`:

    | Ámbito | Límite |
    |---|---|
    | `login` | 20/min |
    | `mfa` | 10/min |
    | `register` | 5/h |
    | `recovery` | 5/h |
    | `activation` | 10/h |
    | `mfa_reset_request` | 3/día |

    Más `limit_req` en Nginx. La IP real se toma de `X-Forwarded-For` solo desde Nginx
    (`NUM_PROXIES=1`).
  - **Anomalías**: `throttle_account_delay`, `throttle_ip_limited` y `credential_stuffing_suspected`
    (10 o más identificadores distintos en 15 min desde una IP).
- **Verificación**: TS-I15, TS-S13, TS-S14, TS-I16 y **TS-S28** (prueba parametrizada por ámbito:
  umbral, 429, `Retry-After` y evento `throttle_ip_limited`; corrección G2).

## R13. Expiración y revocación de sesiones

- **Decisión**:
  - **Inactividad (15 min)**: controlada en el servidor con `last_activity_at`. El
    `SessionLifetimeMiddleware` la renueva con un `UPDATE` directo de metadatos (granularidad de
    60 s), **sin** modificar `session_data` ni reemitir la cookie. `SESSION_SAVE_EVERY_REQUEST =
    False` (decisión C2, alternativa B; se descartó la alternativa de enmendar la constitución).
  - **Absoluta (8 h desde la creación, FR-011)**: `expire_date = created_at + 8 h`, con el `created_at`
    inicial de la sesión (`pre_auth` o login directo) **heredado en cada rotación**. Nunca se
    extiende ni se reinicia, y se comprueba **en
    el propio motor** al cargar, además del `SessionLifetimeMiddleware` como segunda capa.
  - **Cookie**: `__Host-sf_session` sin `Expires` (`SESSION_EXPIRE_AT_BROWSER_CLOSE = True`). Solo
    se emite al crear o rotar la sesión y se elimina en el logout.
  - **Evento `session_expired`**: solo cuando una sesión con `user_id` que el servidor emitió
    válidamente se encuentra caducada al reutilizarse. Nunca por cookies aleatorias, mal formadas,
    inexistentes o ya purgadas (corrección I1).
  - **`pre_auth`**: sin `login()`; caduca a los 5 minutos (10 en un alta obligatoria). Solo accede a
    `/auth/login/mfa`, `/auth/login/enroll/*`, `/auth/login/mfa-reset-request` y `/auth/logout`.
  - **Revocación** (`sessions.revoke_all(user, except_current)`): borra las filas por `user_id`; el
    efecto es inmediato en la siguiente petición (la carga no encuentra la fila). Se aplica según
    FR-012, con la rotación de la clave de la sesión conservada.
  - Una petición en curso que intente guardar tras la revocación recibe `UpdateError` y la sesión no
    se resucita.
- **Verificación**: TS-I06, TS-I07, TS-I08, TS-S15 y la suite TS-SC, incluidas **SC15** (ausencia
  de `Set-Cookie` de sesión en respuestas que no crean ni rotan la sesión), **SC16**
  (`last_activity_at` se actualiza sin que cambie `session_data`) y **SC17** (reglas de emisión de
  `session_expired`) **SC18** (el límite absoluto se mide desde el `created_at` inicial y ninguna
  rotación lo reinicia), **SC19** (pedir el token CSRF o fallar el login no crea sesiones) y **SC20**
  (`_sf_pending_user_id`: correlación sin autenticación y revocación de `pre_auth` y `full`).

## R14. Auditoría, roles de PostgreSQL y separación de funciones

- **Roles y permisos**:

  | Rol | Login | Uso | Permisos |
  |---|---|---|---|
  | `postgres` (superusuario) | Sí (solo administración del contenedor) | Crear roles y la base de datos en la inicialización | Todos. **No** lo usa la aplicación |
  | `securefin_owner` | Sí, solo en el servicio `migrate` | Propietario del esquema `securefin`; ejecuta las migraciones; dueño de tablas y triggers | DDL completo |
  | `securefin_app` | Sí (backend y mailer) | Ejecución de Django | `USAGE` en el esquema, sin `CREATE`. Tablas IAM: SELECT, INSERT, UPDATE, DELETE. **`audit_securityevent`: solo INSERT y SELECT**; `REVOKE UPDATE, DELETE, TRUNCATE`. Sin propiedad de objetos (no puede desactivar triggers ni alterar tablas) |

  - `REVOKE ALL ON SCHEMA public FROM PUBLIC`.
  - Privilegios por defecto (`ALTER DEFAULT PRIVILEGES FOR ROLE securefin_owner`) para las tablas
    IAM, más una migración específica que revoca UPDATE, DELETE y TRUNCATE sobre la tabla de
    auditoría.
  - La credencial de `securefin_owner` solo se monta en el servicio de un solo uso `migrate`. El
    backend y el mailer usan exclusivamente `securefin_app` y se niegan a arrancar si se conectan
    como `securefin_owner` (R8, corrección U1).
- **Retención**: los eventos se conservan durante la vigencia del laboratorio académico. Solo se
  eliminan al desmantelar el entorno, con un procedimiento ejecutado con `securefin_owner` fuera de
  la aplicación y documentado en `docs/security/privacy.md` (corrección C4).
- **Defensas adicionales**:
  1. el modelo bloquea `save()` sobre registros existentes y `delete()`;
  2. triggers `BEFORE UPDATE OR DELETE` (por fila) y `BEFORE TRUNCATE` (por sentencia) que lanzan
     una excepción.
- **Limitaciones (no hay inmutabilidad absoluta)**:
  - El superusuario `postgres` y el propietario `securefin_owner` pueden desactivar triggers,
    modificar o borrar filas y alterar permisos.
  - Quien controle el host o el volumen de datos puede editar los archivos de la base de datos o
    las copias de seguridad.
  - Por tanto, la garantía es **append-only frente a la aplicación y su rol de ejecución**.
  - Mejoras futuras fuera del alcance: cadena de hashes encadenados (detección de manipulación) o
    exportación periódica a un almacenamiento de solo escritura.
- **Fallo cerrado**: el evento se escribe dentro de la `transaction.atomic` de cada operación
  administrativa (FR-044).
- **Separación de funciones**: solo `IsAuditor` accede a `/api/v1/audit/*`; Django Admin
  desactivado.
- **Logs técnicos**: JSON con `request_id` y redacción de claves y cookies sensibles; Nginx sin
  cuerpos ni cookies.
- **Verificación**:
  - TS-S16: con `securefin_app`, UPDATE, DELETE y TRUNCATE fallan;
    `has_table_privilege('securefin_app', 'audit_securityevent', 'UPDATE')` es falso.
  - TS-S26: `securefin_app` no puede `ALTER TABLE` ni `DROP TRIGGER`.
  - TS-S17, TS-I17, TS-S18.

## R15. Autorización (RBAC de función y de objeto)

- **Decisión**:
  - **Matriz** única en `iam/policies/matrix.py`.
  - **Permisos por defecto globales**: `IsFullyAuthenticated`, `HasRolePermission` y
    `IsResourceOwner`. Este último filtra las consultas por propietario: un recurso ajeno no se
    encuentra y responde 404.
  - Rutas `/users/{user_id}/…` con alias `me`; funciones administrativas en `/admin/…`.
- **Verificación**: TS-S01 (generada desde la matriz) y TS-S02.

## R16. Estrategia de pruebas

- **Decisión**: Pytest + `pytest-django` con PostgreSQL real (con los dos roles) en CI; reloj
  inyectable con `unittest.mock`; fixtures propias con identidades ficticias.
  - **Capas**: unitarias, integración, seguridad, **conformidad del motor de sesión (TS-SC)**,
    contrato, aceptación y rendimiento.
  - **Marcadores**: `unit` (sin base de datos), `integration`, `session_conformance`, `security`,
    `contract` y `acceptance` (con PostgreSQL), `stack` (necesita el stack completo de Compose) y
    `e2e` (Playwright contra el stack).
  - **CI en trabajos separados** (correcciones U2 y U4):
    1. `static`: Semgrep, Bandit, pip-audit, npm audit y Trivy `fs`.
    2. `unit`: `pytest -m unit`.
    3. `integration`: servicio PostgreSQL inicializado con los dos roles, y `pytest -m
       "integration or session_conformance or security or contract or acceptance" -m "not stack"`.
    4. `stack`: genera secretos **efímeros** con `openssl rand -base64 32` en el runner (nunca
       secretos reales ni versionados) → `docker compose up -d --wait` (healthchecks de db, backend,
       mailer, mailpit y nginx) → `docker compose run --rm migrate` → `pytest -m stack` y
       `npx playwright test` → Trivy `image` → `docker compose down -v`.
  - **Protección de tokens en E2E (corrección U1)**:
    - `playwright.config.js` con `trace: "off"`, `video: "off"`, `screenshot: "off"` y reporter
      `list` (sin informe HTML).
    - `outputDir` temporal que se borra al terminar.
    - Ningún `console.log`, mensaje de aserción ni log con URLs completas, tokens o cuerpos de
      correo.
    - La CI **no sube** `test-results/` ni `playwright-report/` como artefactos.
    - Los tokens se consumen en la propia prueba, los mensajes se borran de Mailpit al final y el
      entorno se destruye con `docker compose down -v`.
    - Como evidencia se usa un resumen textual sanitizado (nombre de la prueba y resultado; p. ej.
      "fragmento eliminado tras `replaceState`: sí"), nunca el token.
  - **Sin omisiones silenciosas**: `--strict-markers`; un `conftest` hace **fallar** (no omitir)
    las pruebas `stack` y `e2e` si el stack no responde; pytest con 0 pruebas recogidas (código 5)
    hace fallar el trabajo; no se permite `pytest.skip` por falta de infraestructura.
  - Falla con severidad alta o crítica. **Supresiones** según `docs/security/suppressions.md`:
    justificación, alcance (regla y ubicación), responsable, fecha de revisión y aprobación en el PR
    mediante `.github/pull_request_template.md` (corrección C3).
- **Verificación**: trazabilidad FR/SC → pruebas en `plan.md`.

## R17. Dependencias, versiones y bloqueo

**Versiones** (preliminares; se fijan las exactas al crear los archivos de bloqueo y se verifican en
la primera tarea de implementación):

| Componente | Versión objetivo | Estado y criterio |
|---|---|---|
| Python | **3.13** (imagen `python:3.13-slim`) | Django 5.2 es compatible con Python 3.10–3.13 |
| Django | **5.2 LTS, última versión de mantenimiento** (≥ 5.2.17, la última publicada vista, del 4 de agosto de 2026) | Antes de bloquear, comprobar en djangoproject.com si hay una 5.2.x posterior y usarla. Soporte hasta abril de 2028 |
| Django REST Framework | **3.18.x condicionada; 3.16.x como base segura** | Ver evaluación debajo |
| argon2-cffi, cryptography, pyotp, segno, psycopg[binary] 3, gunicorn | Últimas estables compatibles con Python 3.13 | Se fijan con hashes |
| PostgreSQL | 17 | Imagen fijada por *digest* |
| Nginx | estable 1.28 | Imagen fijada por *digest* |
| Mailpit | Última estable (`axllent/mailpit:vX.Y.Z`) | Imagen fijada por *digest* |
| Node.js (solo compilación) | 22 LTS | — |
| React / Vite / react-router | 19 / estable actual / estable actual | `package-lock.json` |

**Evaluación DRF 3.16 → 3.18.1**:

- La 3.18.0 retiró el soporte de Django 4.2, 5.0 y 5.1, añadió Django 6.1 y **cambió el formato de
  los errores de `ListSerializer` (`many=True`) a un diccionario**, lo que rompe la compatibilidad
  hacia atrás.
- **No se pudo confirmar** la publicación ni las notas de la 3.18.1 en esta fase.
- **Criterio de adopción**:
  1. la 3.18.1 está publicada en PyPI;
  2. su matriz de compatibilidad incluye Django 5.2 y Python 3.13;
  3. `pip-compile` resuelve sin conflictos;
  4. la suite completa (incluidas TS-C y TS-SC) pasa.
- **Impacto en este diseño**: bajo. El contrato no usa entradas `many=True` y los errores se emiten
  con un formato propio uniforme.
- Si no se cumple algún criterio, se fija la última 3.16.x compatible, sin actualizar a ciegas.

**Estrategia de bloqueo**:

- **Python**: `requirements.in` con dependencias directas → `pip-compile --generate-hashes`
  (pip-tools, herramienta solo de desarrollo) → `requirements.txt` con todas las transitivas
  fijadas y sus hashes. La instalación usa `pip install --require-hashes --no-deps`.
- **Node**: `package-lock.json` versionado e instalación con `npm ci`.
- **Contenedores**: todas las imágenes base fijadas por etiqueta **y** *digest* (`imagen:tag@sha256:…`)
  y construcción multietapa. El frontend se compila con Node y solo se copian los estáticos a Nginx.
- **Actualizaciones**: nunca sin comprobar la compatibilidad. Las de seguridad de Django 5.2.x se
  aplican tras pasar la suite completa. Los avisos se siguen con pip-audit, npm audit y Trivy en CI.

**Dependencias justificadas** (sin cambios respecto a la revisión 1, más pip-tools):

| Dependencia | Ámbito | Justificación |
|---|---|---|
| Django, DRF | Backend | Stack constitucional |
| argon2-cffi | Backend | Argon2id para contraseñas, códigos de recuperación y códigos de verificación |
| cryptography | Backend | AES-256-GCM (Principio III) |
| pyotp | Backend | TOTP RFC 6238 (django-otp guarda el secreto en claro) |
| segno | Backend | QR en SVG sin dependencias |
| psycopg 3 | Backend | Driver de PostgreSQL |
| gunicorn | Backend | Servidor WSGI |
| pytest, pytest-django, pytest-cov | Pruebas | Principio V |
| pip-tools | Desarrollo | Bloqueo con hashes |
| Semgrep, Bandit, pip-audit, npm audit, Trivy | CI | SAST, SCA y contenedores |
| `@playwright/test` (`devDependencies` del frontend) | Pruebas E2E | **Obligatoria** (corrección G3). Es la única forma reproducible de verificar comportamientos que solo existen en el navegador: atributos `autocomplete`, pegado de contraseñas y compatibilidad con gestores (FR-005), y limpieza del fragmento con el token (R7, TS-S24). Solo se usa en desarrollo y CI; no forma parte de la imagen ni del bundle de producción |

**No se añaden**: Redis, Celery, `django-cors-headers`, `djangorestframework-simplejwt`,
`django-otp`, `django-axes`, `django-ratelimit`, `freezegun` ni `drf-spectacular`.

## Observaciones fuera del alcance

- El cambio voluntario de contraseña con sesión iniciada está declarado fuera del alcance en la spec
  (Out of Scope), y FR-012 enumera los cambios de credenciales contemplados (corrección S2).
- Mejoras opcionales: doble aprobación de reinicios de MFA sobre Administradores; cadena de hashes
  en la auditoría.
