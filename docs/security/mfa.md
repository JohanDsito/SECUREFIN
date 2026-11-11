# MFA: TOTP cifrado, códigos de recuperación y fase `pre_auth`

**Requisitos**: FR-008, FR-012, FR-024 a FR-031, FR-049. **Decisiones**: research R5, R6, R8, R13.
**Código**: `backend/apps/iam/crypto/aead.py`, `backend/apps/iam/models/mfa.py`,
`backend/apps/iam/services/{mfa,recovery_codes,authentication}.py`, `backend/apps/iam/api/views/mfa.py`.
**Pruebas**: `tests/unit/test_aead.py` (TS-U03/U04), `tests/integration/test_mfa.py` (TS-I09/I10),
`tests/security/test_pre_auth.py` (TS-S15), `tests/contract/test_mfa_contract.py` y
`tests/acceptance/test_us3_mfa.py` (TS-A03).

## TOTP

| Parámetro | Valor | Motivo |
|---|---|---|
| Secreto | 160 bits de `secrets.token_bytes`, en base32 (32 caracteres) | Longitud recomendada por RFC 4226 |
| Algoritmo | HMAC-SHA-1, 6 dígitos, periodo de 30 s (`pyotp`) | Compatibilidad con todas las apps autenticadoras |
| Tolerancia | ±1 intervalo (FR-026) | Desfase de reloj razonable sin ampliar demasiado la ventana |
| Formato aceptado | Exactamente `[0-9]{6}` ASCII | `str.isdigit()` aceptaría dígitos de otros sistemas de escritura |

**Antirrepetición.** Cada dispositivo guarda `last_used_timestep`. Solo se acepta un código cuyo
intervalo sea **estrictamente posterior** al último usado. La comprobación y la actualización ocurren
bajo `select_for_update` sobre la fila del dispositivo: si llegan dos peticiones con el mismo código a
la vez, una gana y la otra recibe el rechazo (`test_concurrent_totp_code_accepted_once`). Un código ya
usado no sirve aunque siga dentro de su ventana de 90 s.

La comparación usa `hmac.compare_digest`. El tiempo sale de `apps.core.clock`, lo que permite
probar la tolerancia y la caducidad con un reloj simulado.

## Cifrado del secreto: AES-256-GCM con AAD

El servidor necesita el secreto en claro para calcular el código esperado, así que **no puede
guardarse como hash** (a diferencia de las contraseñas o los códigos de recuperación). Se guarda
cifrado:

- **AES-256-GCM** (`cryptography`), cifrado autenticado: cualquier alteración del texto cifrado, del
  nonce o de la AAD hace fallar el descifrado (etiqueta de 128 bits).
- **Nonce aleatorio de 96 bits por operación** (`os.urandom`). Reutilizar un nonce con la misma clave
  rompería GCM; con nonces aleatorios de 96 bits la probabilidad de colisión es despreciable para
  este volumen.
- **AAD = `"securefin:totp:v1:" + user.id`**. Liga el texto cifrado a su usuario: si alguien con
  acceso de escritura a la base copia el secreto cifrado de una víctima a su propia fila, el
  descifrado falla (`test_ciphertext_moved_to_another_user_fails_authentication`).
- **Clave dedicada** `TOTP_ENCRYPTION_KEYS[vN]` (exactamente 32 bytes), distinta de todas las demás y
  fuera de la base de datos (secretos de Docker). Un volcado de la base sin la clave no revela ningún
  secreto.
- **Rotación**: `python manage.py iam_rotate_totp_key --to v2` recifra todos los dispositivos en una
  única transacción, con nonce nuevo cada uno, y solo imprime el recuento. Si un dispositivo no se
  puede descifrar, no se recifra ninguno.
- **Fallo cerrado**: un texto cifrado alterado, trasplantado desde la fila de otro usuario o cifrado
  con una versión de clave ya retirada no se descifra. El servicio lo trata como código incorrecto
  (`401` en el login, `400` en una operación autenticada, nunca `500`) y registra `totp_rejected` con
  `reason: "decryption_failed"`.

El secreto se devuelve **una sola vez**, en la respuesta de alta, con `Cache-Control: no-store`. El
SPA lo muestra en texto y como QR (SVG generado con `segno`, enviado como `data:` URI y mostrado en
`<img>`, compatible con la CSP `img-src 'self' data:`). Al confirmar, el componente lo descarta.

## Alta, reconfiguración y desactivación

- **Alta**: `setup` crea un dispositivo `pending` (caduca a los **10 minutos**). `confirm` exige un
  código válido de ese secreto. Solo entonces el dispositivo pasa a `active` y se generan los códigos
  de recuperación. Sin confirmación no hay MFA ni códigos (escenario 2).
- **Reconfiguración** (FR-031): exige la contraseña en `setup` y un código del **nuevo** dispositivo
  en `confirm`. Sirve, por ejemplo, tras iniciar sesión con un código de recuperación por pérdida del
  móvil. Al confirmar, el dispositivo anterior se borra y su lote de códigos queda invalidado.
- **Desactivación** (FR-027): solo roles con MFA opcional (Cliente), con contraseña y código válido.
  Para Administrador y Auditor la capa de función responde `403` (el permiso `mfa.disable_self` no
  está en su rol) y el servicio lo vuelve a comprobar.

### Desviación del modelo de datos

El data-model definía `TOTPDevice.user` como OneToOne. Con un único dispositivo por usuario, empezar
una reconfiguración obligaría a sustituir el dispositivo activo antes de confirmar el nuevo, y
abandonarla a medias dejaría la cuenta **sin MFA**. Se implementa como FK y el activo solo se
sustituye al confirmar (`test_reconfiguration_keeps_active_device_until_confirmed`).

La invariante "como máximo un `active` y un `pending` por usuario" se impone en la base con **dos
restricciones únicas condicionales** (índices únicos parciales de PostgreSQL:
`iam_totp_one_active_per_user` e `iam_totp_one_pending_per_user`), no con `unique(user, status)`.
La unicidad solo afecta a los estados abiertos: si en el futuro se conservan dispositivos históricos
(p. ej. un estado `revoked`), podrán acumularse sin tocar estas restricciones. Hoy no hay histórico:
desactivar o reconfigurar borra el dispositivo anterior.

### Concurrencia

Todas las operaciones que cambian el MFA de un usuario (alta, confirmación, desactivación y
generación de un lote de códigos) empiezan bloqueando la fila del usuario (`lock_user_mfa`, `SELECT
... FOR UPDATE`) y después sus dispositivos o códigos, siempre en ese orden (sin interbloqueos):

- dos altas simultáneas ya no terminan en `IntegrityError` (500): una espera a la otra y queda un
  único `pending`;
- dos confirmaciones simultáneas del mismo código: una activa el dispositivo y la otra se rechaza;
  nunca hay dos dispositivos activos (y, como última barrera, el índice único parcial lo impediría);
- dos generaciones simultáneas de lote dejan un único lote de 10 códigos, no 20.

Los hashes Argon2id de un lote nuevo se calculan **antes** de tomar el bloqueo.

## Códigos de recuperación

- **10 por lote, 28 caracteres de base32 de Crockford = 140 bits** cada uno (por encima de los 128
  exigidos). El alfabeto evita I, L, O y U. Se muestran agrupados de 4 en 4. La entrada acepta
  minúsculas, espacios y guiones, y mapea I/L→1 y O→0.
- **Solo se guarda un verificador Argon2id** (m=19 MiB, t=2, p=1) por código. Con 140 bits de
  entropía un ataque fuera de línea es inviable; el coste moderado mantiene el peor caso (10
  verificaciones) por debajo de medio segundo.
- **Uso único**: la verificación y el marcado como `used` ocurren en la misma transacción con
  `select_for_update` sobre los códigos disponibles del usuario
  (`test_concurrent_recovery_code_consumed_once`). La respuesta indica cuántos quedan (FR-029).
- **Regenerar** (FR-030) exige contraseña y TOTP, y marca el lote anterior como `invalidated`.
- **Solo una vez en pantalla**: el SPA los guarda en el estado del componente, nunca en
  `localStorage`, `sessionStorage`, cookies ni la URL. La descarga `.txt` la genera el navegador con
  un `Blob`, sin pasar por el servidor.

## Fase `pre_auth`

Tras una contraseña válida:

| Situación | Respuesta | Sesión |
|---|---|---|
| MFA activo | `mfa_required` | `pre_auth`, 5 min |
| Rol con MFA obligatorio sin MFA (Administrador, Auditor) | `mfa_enrollment_required` | `pre_auth` de alta, 10 min |
| Cliente sin MFA | `authenticated` | `full` |

La sesión `pre_auth` guarda `_sf_pending_user_id` y **no** llama a `login()`: `request.user` sigue
anónimo, así que `IsFullyAuthenticated` responde `401` en **todas** las rutas protegidas
(`test_pre_auth_gives_no_access_to_protected_routes`). Solo responden `/auth/login/mfa`,
`/auth/login/enroll/*` y `/auth/logout`.

- **Usuario pendiente vigente**: si el usuario se desactiva o se le revocan las sesiones, la sesión
  `pre_auth` deja de valer de inmediato.
- **Sin "re-alta" para evitar el MFA**: con MFA activo, los endpoints de alta responden `401`. De lo
  contrario, quien conociera la contraseña podría dar de alta su propio autenticador y saltarse el
  segundo factor (`test_user_with_active_mfa_cannot_re_enroll_from_pre_auth`).
- **Paso a `full`**: `login()` rota la clave de sesión (anti-fijación) y la sesión hereda el
  `created_at` inicial, de modo que el límite absoluto de 8 h cuenta desde la contraseña.
- **Fallos**: respuesta `401` genérica, evento `login_failed` con `stage: "mfa"`. La limitación de
  intentos por cuenta e IP llega con US5.

## MFA obligatorio por rol

`ROLE_MFA_REQUIRED` es un atributo del rol (FR-025); un rol nuevo lo exige por defecto. Un
Administrador o Auditor sin MFA solo puede completar el alta. `IsFullyAuthenticated` vuelve a
comprobar en cada petición que el MFA del rol sigue activo.

## Revocación al cambiar el MFA (FR-012)

Activar, desactivar o reconfigurar el MFA, o regenerar los códigos, revoca **las demás** sesiones
del usuario y rota la clave de la actual (`session_admin.rotate_after_mfa_change`). El límite absoluto
no se reinicia.

## Eventos

`mfa_enabled`, `mfa_reconfigured`, `mfa_disabled`, `recovery_codes_regenerated`,
`recovery_code_used` (con `remaining`), `totp_rejected` (código rechazado en una operación
autenticada o en el alta), `login_failed` (`stage: "mfa"` en el login y `stage: "reauth"` si falla la
contraseña de una reautenticación) y `login_succeeded` (con `mfa_method`). Ninguno incluye secretos
ni códigos.
