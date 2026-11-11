# Sesiones: motor con verificadores HMAC, CSRF sin CORS y ciclo de vida

**Requisitos**: FR-008 a FR-013, FR-025. **Decisiones**: research R2, R3, R13; correcciones C2, I1,
I3 y U3. **Código**: `backend/apps/iam/sessions/` y `backend/apps/iam/services/session_admin.py`.

## Por qué sesiones de servidor y no JWT

El SPA React se sirve desde el **mismo origen** que la API. Una cookie `HttpOnly` no es legible por
JavaScript (protege frente a XSS), se revoca al instante borrando la fila y no necesita dependencias.
Un JWT en `localStorage` sería exfiltrable y exigiría listas de revocación.

## Cookie

`__Host-sf_session`, con los atributos `Secure`, `HttpOnly`, `SameSite=Strict` y `Path=/`, sin
`Domain` y sin `Expires`.

- El prefijo `__Host-` obliga al navegador a exigir `Secure`, `Path=/` y ausencia de `Domain`.
- La cookie **solo se emite al crear o rotar la sesión**; ninguna otra respuesta la reemite
  (`SESSION_SAVE_EVERY_REQUEST = False`). Así se cumple que un token no aparezca en respuestas
  posteriores a su emisión (Principio III).

## Qué se guarda en PostgreSQL

| Dato | Almacenamiento |
|---|---|
| Identificador de sesión | **Nunca** en claro: `"<versión>$" + HMAC-SHA-256(SESSION_HMAC_KEYS[versión], "securefin:session:" + clave)` |
| Clave HMAC | Exclusiva para sesiones, versionada y fuera de la base de datos (`/run/secrets`) |
| Modelo | `UserSession` sin ningún campo `session_key`; la tabla `django_session` no existe |

Si algún código heredado de Django intentara filtrar por `session_key=`, el ORM lanzaría
`FieldError`: el diseño falla de forma cerrada.

## Ciclo de vida

| Fase | Regla |
|---|---|
| Nacimiento | Solo tras validar la contraseña. Pedir el token CSRF **no** crea sesión |
| `pre_auth` | MFA pendiente; `_sf_pending_user_id` correlaciona al propietario sin autenticarlo; caduca a los 5 min (10 en un alta) |
| `full` | Tras `login()`, que **rota la clave** (anti-fijación) |
| Inactividad | 15 min, medida con `last_activity_at`, que se renueva en el servidor (cada 60 s como mucho) sin tocar los datos ni reemitir la cookie |
| Límite absoluto | 8 h desde el `created_at` **inicial**; las rotaciones lo heredan y nunca lo reinician |
| Revocación | `revoke_all(user)` borra las filas `pre_auth` y `full`; una petición en curso no puede resucitar una sesión revocada (UPDATE sin upsert) |
| Cookies desconocidas | Una cookie aleatoria, mal formada o retirada nunca se adopta y no genera eventos |

## CSRF sin CORS

- `CsrfViewMiddleware` y `SessionAuthentication` de DRF.
- Las vistas anónimas que cambian estado (login, registro, recuperación…) llevan `csrf_protect`
  para evitar el *login CSRF*.
- El SPA lee la cookie `__Host-sf_csrftoken` y la reenvía en `X-CSRFToken`. Esa cookie no es una
  credencial y no depende de la sesión.
- No se emite ninguna cabecera CORS: la política del navegador bloquea los orígenes ajenos.

## Rotación de la clave HMAC

1. Añadir `session_hmac_key_v2` y fijar `SESSION_HMAC_KEY_VERSIONS=v2,v1`. Las sesiones `v1` siguen
   siendo válidas hasta 8 h.
2. Después, `SESSION_HMAC_KEY_VERSIONS=v2` y `python manage.py iam_rotate_session_key --retire v1`.
3. En una emergencia, se retira `v1` de inmediato: todo el mundo vuelve a iniciar sesión.

## Verificación

- Suite de conformidad TS-SC01–SC20 (`pytest -m session_conformance`). Es **obligatoria antes de
  actualizar Django**.
- TS-S04 (atributos de cookie) y TS-S05/S06/S07 (CSRF y CORS).
