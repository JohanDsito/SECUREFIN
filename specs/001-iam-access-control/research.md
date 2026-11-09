# Research: Feature 001 — Sistema de Identidad y Control de Acceso (IAM)

**Fecha**: 2026-11-08 (revisión 2) | **Plan**: [plan.md](./plan.md) | **Spec**: [spec.md](./spec.md)

Cada decisión sigue el formato exigido: alternativas, decisión, justificación, riesgos, mitigaciones
y verificación. Los identificadores `T-xx` remiten al análisis STRIDE de `plan.md`; los `TS-xx`, a
la estrategia de pruebas.

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
| Inactividad (FR-011) | Nativa | Hay que construirla | Hay que construirla |
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
| `expire_date` | timestamptz, índice | Inactividad: ahora + 15 min, renovado en cada petición |
| `public_id` | uuid, único | Identificador expuesto en la API (nunca el verificador) |
| `user_id` | FK nulo, índice | Desnormalizado desde los datos de sesión al guardar |
| `auth_level` | `varchar(10)` | `anonymous` \| `pre_auth` \| `full` |
| `created_at` | timestamptz | Solo se fija al insertar |
| `authenticated_at` | timestamptz nulo | Base del límite absoluto de 8 h; se conserva al rotar la clave |
| `last_activity_at` | timestamptz | |
| `ip_address` / `user_agent` | inet / `varchar(200)` | Para que el usuario reconozca sus sesiones |

**No existe ningún campo llamado `session_key`.** Si cualquier método heredado de Django no
sobrescrito intentara filtrar por `session_key=`, el ORM lanzaría `FieldError`, así que el diseño
**falla de forma cerrada** en lugar de consultar en claro. Además, `django.contrib.sessions` **no se
instala**, para que no se cree la tabla `django_session` y no haya ninguna caída accidental al
modelo por defecto.

### R2.4 Funcionamiento del motor (`iam.sessions.store.SessionStore`)

- **Base**: subclase de `django.contrib.sessions.backends.db.SessionStore` con `get_model_class()`
  → `UserSession`.
- **Claves**: `SESSION_HMAC_KEYS` (mapa versionado: una versión activa más las anteriores
  aceptadas), **independiente** de `DJANGO_SECRET_KEY` y de las claves de tokens y TOTP.
- **Verificador**:
  `verifier(v, k) = v + "$" + hex(HMAC-SHA-256(SESSION_HMAC_KEYS[v], "securefin:session:" + k))`.

| Operación | Comportamiento |
|---|---|
| Generación (`_get_new_session_key`) | `secrets.token_urlsafe(32)` (256 bits, CSPRNG); se reintenta si `exists()` |
| Creación (`create`) | Bucle: clave nueva → `save(must_create=True)`; una `IntegrityError` provoca reintento. Inserta con el verificador de la **versión activa** |
| Guardado (`save`, `create_model_instance`) | Construye la fila con `key_verifier`, datos, `expire_date` y los metadatos (`user_id`, `auth_level`, `authenticated_at` leídos de los datos de sesión). Si `must_create=False` usa `force_update` **sin** `update_or_create`: si la fila fue revocada entretanto, Django lanza `UpdateError` y la sesión **no se resucita** (el middleware responde `SessionInterrupted`) |
| Carga (`load`, `_get_session_from_db`) | Calcula el verificador para cada versión aceptada (activa primero) y busca `key_verifier = X AND expire_date > now`. Rechaza y borra si `authenticated_at + 8 h < now`, o si es `pre_auth` y supera 5/10 min. Si no la encuentra, fija `self._session_key = None` y devuelve `{}`: **nunca adopta un identificador que no haya emitido** (anti-fijación) |
| Existencia (`exists`) | Verificadores de todas las versiones aceptadas |
| Borrado (`delete`) | `DELETE` por verificadores; sin argumento, usa la clave actual |
| Rotación (`cycle_key`) | Comportamiento de Django (crear una nueva con los mismos datos y borrar la anterior), conservando `authenticated_at` salvo en el login |
| Limpieza (`clear_expired`) | Borra si `expire_date < now` o si `authenticated_at < now − 8 h` |
| API asíncrona de Django 5.x (`aload`, `asave`, `acreate`, `aexists`, `adelete`, `acycle_key`, `aclear_expired`) | Se sobrescriben y lanzan `NotImplementedError`: el proyecto es WSGI síncrono, y así no hay rutas heredadas sin revisar |

### R2.5 Integración con Django

| Pieza de Django | Interacción |
|---|---|
| `SessionMiddleware` | Carga y guarda mediante el motor; escribe la cookie con la clave en claro **solo** hacia el navegador |
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
- **Verificación**: suite de conformidad TS-SC01–SC14 (Test Strategy de `plan.md`).

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
  | Recuperación de contraseña | **30 min** | ⚠️ La spec vigente fija **15 min** (FR-046, US7-2). Mientras no se enmiende, rige el valor de la spec. El parámetro `PASSWORD_RESET_TTL` es configurable |
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
| `TOKEN_HMAC_KEYS` | Verificadores de tokens (R7) y resúmenes de limitación (`"throttle:"`) | Sí |
| `TOTP_ENCRYPTION_KEYS` | AES-256-GCM de los secretos TOTP (R5) | Sí |
| Contraseñas de los roles de PostgreSQL | `owner` (solo migraciones) y `app` (ejecución) | — |

- `core.keys` valida al arrancar: presencia, al menos 32 bytes y **todas distintas entre sí**. Si
  algo falla, no arranca.
- El contenedor de ejecución **no monta** la credencial del rol `owner` (R14).
- **Rotación y pérdida**:

  | Clave | Rotación planificada | Pérdida o compromiso |
  |---|---|---|
  | Sesión | R2.6 | Se cierran todas las sesiones |
  | Tokens | `v2` activa; `v1` aceptada hasta 24 h | Se invalidan los tokens pendientes y se reinician los contadores de limitación |
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
- **Verificación**: TS-S09 (Δ medio < 100 ms en 200 peticiones, con Mailpit activo **y detenido**),
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
  - Su interfaz solo se consulta a través de un `server` de Nginx publicado **solo** en
    `127.0.0.1:8025`, con doble autenticación: básica en Nginx y archivo de autenticación de
    Mailpit.
  - Sin `MP_SMTP_RELAY_*`, así que no hay relay ni "liberación" de mensajes.
  - Retención de 200 mensajes y 24 h.
  - Bloqueo de recursos remotos en la vista HTML.
- **Django (proceso `mailer`)**: `EmailBackend` SMTP hacia `mailpit:1025` sin TLS (**excepción
  E3** en Complexity Tracking). El backend `locmem` se usa en las pruebas.
- **Evidencias**: con los tokens ocultos o usando tokens ya consumidos o caducados.
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
  - **Por cuenta**: modelo `AuthThrottle` con la clave `HMAC(TOKEN_HMAC_KEYS, "throttle:acct:" +
    email normalizado)`. Desde el 5.º fallo, retrasos de 30, 60, 120, 240 y 480 s, y después 900 s
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
- **Verificación**: TS-I15, TS-S13, TS-S14, TS-I16.

## R13. Expiración y revocación de sesiones

- **Decisión**:
  - **Inactividad**: `SESSION_COOKIE_AGE = 900` con `SESSION_SAVE_EVERY_REQUEST = True`.
  - **Absoluta**: comprobada **en el propio motor** (`load` con `authenticated_at + 8 h`), además del
    `SessionLifetimeMiddleware` como segunda capa.
  - **`pre_auth`**: sin `login()`; caduca a los 5 minutos (10 en un alta obligatoria). Solo accede a
    `/auth/login/mfa`, `/auth/login/enroll/*`, `/auth/login/mfa-reset-request` y `/auth/logout`.
  - **Revocación** (`sessions.revoke_all(user, except_current)`): borra las filas por `user_id`; el
    efecto es inmediato en la siguiente petición (la carga no encuentra la fila). Se aplica según
    FR-012, con la rotación de la clave de la sesión conservada.
  - Una petición en curso que intente guardar tras la revocación recibe `UpdateError` y la sesión no
    se resucita.
- **Verificación**: TS-I06, TS-I07, TS-I08, TS-S15 y la suite TS-SC.

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
  - La credencial de `securefin_owner` solo se monta en el servicio de un solo uso `migrate`.
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
  - **CI**: pytest con cobertura → Semgrep y Bandit → pip-audit y npm audit → construcción → Trivy
    `image` y `fs --scanners misconfig,secret`. Falla con severidad alta o crítica, y las
    supresiones se justifican en el PR.
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
| Playwright (solo en CI, opcional) | Pruebas | TS-S24 (limpieza del fragmento en el navegador). Si se descarta, TS-S24 pasa a ser una verificación manual documentada |

**No se añaden**: Redis, Celery, `django-cors-headers`, `djangorestframework-simplejwt`,
`django-otp`, `django-axes`, `django-ratelimit`, `freezegun` ni `drf-spectacular`.

## Observaciones fuera del alcance

- La spec no incluye un cambio voluntario de contraseña con sesión iniciada.
- **Discrepancia con la spec**: la caducidad de recuperación de 30 min exige enmendar FR-046 y el
  escenario 2 de US7 (hoy 15 min) antes de `/speckit-tasks`.
- Mejoras opcionales: doble aprobación de reinicios de MFA sobre Administradores; cadena de hashes
  en la auditoría.
