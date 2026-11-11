# Protección frente a intentos repetidos (fuerza bruta y relleno de credenciales)

**Requisitos**: FR-036 a FR-039, FR-049. **Decisión**: research R12. **Código**:
`backend/apps/iam/services/throttling.py`, `backend/apps/iam/models/throttle.py`,
`backend/apps/iam/services/authentication.py`, `backend/apps/iam/api/throttles.py`,
`infra/nginx/nginx.conf`. **Pruebas**: `tests/integration/test_throttling.py` (TS-I15/I16),
`tests/security/test_bruteforce.py` (TS-S13/S14), `tests/security/test_ip_rate_limits.py` (TS-S28) y
`tests/acceptance/test_us5_bruteforce.py` (TS-A05). **Evidencias**: `evidence/E5` y `evidence/E6`.

## Tres capas

| Capa | Qué limita | Umbral | Respuesta |
|---|---|---|---|
| **Nginx** (`limit_req`, `limit_conn`) | Peticiones por IP, antes de llegar a Django | auth 10 r/s (ráfaga 20), api 30 r/s (60), web 50 r/s (100); 20 conexiones por IP | `429` |
| **Django por IP** (throttles de DRF) | Intentos por IP y ámbito | login 20/min, mfa 10/min, register 5/h, activation 10/h, mfa_reset_request 3/día | `429` + `Retry-After` + `throttle_ip_limited` |
| **Django por cuenta** (`AuthThrottle`) | Fallos consecutivos sobre **un identificador**, venga de donde venga | Desde el 5.º fallo: 30, 60, 120, 240, 480 s y después 900 s (tope) | `401` genérico, sin evaluar credenciales + `throttle_account_delay` |

Las dos primeras frenan a quien ataca desde una IP. La tercera frena a quien ataca **una cuenta desde
muchas IPs** (botnet), que es justo lo que la limitación por IP no ve.

## Por qué retrasos progresivos y no bloqueo rígido

Un bloqueo rígido ("5 fallos y la cuenta queda bloqueada hasta que un administrador la desbloquee")
convierte la protección en un arma: un atacante que conoce el correo de la víctima la deja sin acceso
cuando quiera (denegación de servicio sobre la cuenta). Con retrasos progresivos:

- el atacante pasa de miles de intentos por minuto a, como mucho, **unos 13 por hora y cuenta**. Si
  sigue fallando sin parar, tras el 10.º fallo solo puede intentarlo cada 15 min (4 por hora). Su mejor
  estrategia es hacer 10 intentos en unos 15 min y esperar 30 min sin fallar para que el contador se
  reinicie: 10 intentos cada ~45 min. Con contraseñas de 15 caracteres o más y TOTP, inviable;
- la víctima, en el peor caso, **espera 15 minutos**; nunca queda bloqueada para siempre (FR-038,
  escenario 6 de US5).

## Comportamiento por cuenta

- **Durante el retraso** el intento se rechaza **antes** de tocar el hasher Argon2id, el descifrado
  TOTP o los códigos de recuperación, con el mismo `401` y el mismo cuerpo que un fallo normal. El
  evento `login_failed` lleva `reason=throttled`. La prueba lo verifica contando las llamadas al hasher.
- **Cuentan como fallo**: contraseña errónea, cuenta inexistente, cuenta no activa, código TOTP erróneo
  y código de recuperación erróneo. Los intentos rechazados durante el retraso **no** cuentan (no se
  evalúan) y no alargan el retraso.
- **Reinicio del contador**: tras 30 minutos sin fallos, o tras una **autenticación completa**.
  - Con MFA, la contraseña correcta **no** reinicia el contador: solo lo hace completar el segundo
    factor. Si no fuera así, quien ya conoce la contraseña podría alternar "contraseña correcta →
    código TOTP al azar" sin llegar nunca a los 5 fallos, y probar códigos sin límite
    (`test_correct_password_does_not_reset_counter_for_mfa_users`).
- **Cuentas inexistentes**: el estado se guarda por HMAC del correo, sin relación con la tabla de
  usuarios, así que un correo inexistente acumula fallos y recibe retrasos exactamente igual. Las
  respuestas son idénticas byte a byte (`test_unknown_identifier_behaves_like_existing_account`).

## Privacidad y claves

- `AuthThrottle.key_digest` = HMAC-SHA-256(`THROTTLE_HMAC_KEYS[v]`, `"throttle:acct:"` + correo
  normalizado). El correo nunca se guarda; la clave es exclusiva de este propósito (C1).
- **Rotación**: con una versión nueva activa y la anterior aceptada, `check()` consulta los resúmenes de
  todas las versiones y aplica el retraso más restrictivo, de modo que un retraso vigente no se pierde.
  El siguiente fallo se registra con la versión activa heredando el contador, y la fila antigua se
  elimina (`test_key_rotation_checks_all_versions_and_inherits_counter`).
- Las actualizaciones usan `SELECT … FOR UPDATE`: cinco fallos simultáneos cuentan como cinco
  (`test_concurrent_failures_are_all_counted`).

## Detección de relleno de credenciales (FR-039)

Si desde una misma IP fallan **10 o más identificadores distintos en 15 minutos**, se registra
`credential_stuffing_suspected` (una vez por ventana) con la IP en `source_ip` y, en los metadatos,
solo el recuento y la ventana. Por IP se guarda temporalmente (15 min, en la caché de base de datos)
un prefijo del resumen HMAC de cada identificador, nunca el correo. Es una **alerta**: el freno lo
ponen el límite por IP y el de cada cuenta.

## Sin Redis

El estado por cuenta vive en PostgreSQL (`iam_auththrottle`) y los contadores por IP en la caché de
base de datos de Django (`securefin_cache`). Para el volumen de un laboratorio basta, y evita otro
servicio con datos que proteger. Con mucho tráfico, Redis sería más eficiente para los contadores por IP.

## Riesgos y límites conocidos

| Riesgo | Explicación | Mitigación |
|---|---|---|
| **NAT compartida** | Usuarios legítimos detrás de la misma IP pública (universidad, empresa) comparten el límite por IP: 20 logins por minuto entre todos | Umbrales holgados; la limitación por cuenta no se ve afectada; en producción, ajustar por ámbito |
| Atacante que retrasa a la víctima | Puede mantener a la víctima en un retraso de hasta 15 min mientras siga fallando | Tope de 900 s, sin bloqueo permanente; la recuperación de contraseña (US7) no dependerá de este contador |
| Detección aproximada | La anotación por IP no es atómica; con fallos simultáneos puede contar alguno de menos | Solo afecta a la alerta, no al freno |
| Purga | Las filas de `AuthThrottle` se acumulan | `iam_purge_expired` (T117) borra solo filas sin retraso vigente y sin fallos en 30 min, o de versiones de clave retiradas |
| DDoS distribuido | Miles de IPs superan cualquier límite por IP | Fuera del alcance de la aplicación: CDN/WAF del proveedor |
