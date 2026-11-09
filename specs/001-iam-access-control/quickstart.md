# Quickstart y guía de validación: Feature 001 — IAM

**Fecha**: 2026-11-08 (revisión 2) | **Plan**: [plan.md](./plan.md) | **Contrato**: [contracts/iam-api.md](./contracts/iam-api.md)

Guía para levantar el laboratorio y demostrar de extremo a extremo que la feature cumple la spec.
Los archivos de infraestructura se crean durante la implementación. Aquí solo se describe cómo
validarlos.

## 1. Requisitos previos

- Docker y Docker Compose v2, OpenSSL, cURL, `jq`, `psql` (cliente) y Python 3.13. Opcionales:
  Postman, Apache Benchmark y Nmap.
- `hosts`: `127.0.0.1 securefin.local`.
- Solo identidades ficticias (`@lab.securefin.local`).

## 2. Secretos (nunca se suben al repositorio)

```bash
mkdir -p secrets
for k in django_secret_key session_hmac_key_v1 token_hmac_key_v1 throttle_hmac_key_v1 \
         totp_key_v1 db_owner_password db_app_password; do
  openssl rand -base64 32 > "secrets/$k"
done
# + credenciales de la autenticación básica de Nginx y de Mailpit para la interfaz del buzón
# + CA de laboratorio y certificado para securefin.local con OpenSSL
```

**Resultado esperado**: si alguna clave falta, mide menos de 32 bytes o coincide con otra, el
backend **no arranca** y no revela valores (TS-U07).

## 3. Arranque

```bash
docker compose up -d --build db mailpit nginx backend mailer
docker compose run --rm migrate          # único servicio con la credencial de securefin_owner
docker compose exec backend python manage.py iam_bootstrap_admin \
  --email admin1@lab.securefin.local --name "Admin Uno"
```

**Resultado esperado**: la salida no contiene ningún token. El `mailer` entrega la activación en
Mailpit (`https://127.0.0.1:8025`, a través de Nginx con TLS y doble autenticación con la misma
credencial Basic). Repetir el bootstrap
falla porque ya existe un Administrador.

## 4. Comprobaciones de infraestructura (TS-S10, TS-S11, TS-S25, TS-S26)

| Comprobación | Cómo | Esperado |
|---|---|---|
| Solo Nginx publica puertos | `docker compose config` | Nginx: `443`, `80` y `127.0.0.1:8025`. `mailpit`, `db`, `backend` y `mailer`: sin `ports` |
| Redes | `docker network inspect` | `app_net`, `data_net` y `mail_net` con `Internal: true`. Mailpit solo en `mail_net`. El backend web no comparte red con Mailpit; `mailer` y Mailpit solo comparten `mail_net`. Nginx no está en `data_net` |
| Exposición externa | Desde otra máquina: `nmap -p 25,1025,5432,8000,8025 <ip_host>` | Todos cerrados o filtrados; solo `80` y `443` abiertos |
| Interfaz y API de Mailpit | `curl -I --cacert <CA> https://127.0.0.1:8025` sin credenciales, y `curl -u $MAILPIT_API_USER:$MAILPIT_API_PASSWORD --cacert <CA> https://127.0.0.1:8025/api/v1/messages` | `401` sin credenciales; `200` con la credencial (validada por Nginx y por Mailpit); `http://127.0.0.1:8025` no sirve contenido en claro |
| CSRF sin sesión | `curl -sk -c jar.txt https://securefin.local/api/v1/auth/csrf` y `psql`: `SELECT count(*) FROM securefin.iam_usersession` | Solo la cookie `__Host-sf_csrftoken`; el número de filas no cambia (SC19) |
| Sin relay | `docker compose config` del servicio `mailpit` | Ninguna variable `MP_SMTP_RELAY_*` |
| Roles de PostgreSQL | `psql` como `securefin_app`: `SELECT has_table_privilege('securefin.audit_securityevent','UPDATE')` y luego `UPDATE`, `DELETE`, `TRUNCATE`, `ALTER TABLE` y `DROP TRIGGER` | `false`; todas las operaciones fallan |
| Sin sesiones en claro | `psql`: `\d securefin.iam_usersession` y `\dt securefin.django_session` | No hay columna `session_key`; la tabla `django_session` no existe |

## 5. Escenarios funcionales con cURL

Preparación común:

```bash
B=https://securefin.local/api/v1; J=jar.txt
H=(-H "Origin: https://securefin.local" -H "Content-Type: application/json")
curl -sk -c $J -b $J $B/auth/csrf -o /dev/null
CSRF=$(awk '/__Host-sf_csrftoken/ {print $7}' $J)
```

| # | Escenario | Esperado | Spec |
|---|---|---|---|
| V0 | Registro y primer login cronometrados con 5 usuarios ficticios (SC-001) | Los 5 por debajo de 2 minutos; tiempos anotados en `docs/security/evidence/sc-001.md` | SC-001 |
| V1 | Registro con contraseña de 15 caracteres o más | `201`; `password` empieza por `argon2$argon2id$v=19$m=65536,t=3,p=1$` (prefijo de algoritmo de Django) | US1-1 |
| V2 | Registro con `"role": "admin"` | `400` | US1-2 |
| V3 | Contraseña de 14 caracteres / `securefin-gateway-2026` | `400` con la regla incumplida | US1-3 |
| V4 | POST sin `X-CSRFToken` | `403` | R3 |
| V5 | Login correcto y dos peticiones posteriores a `/auth/session` | El login da `200` con cookie `__Host-sf_session` (`HttpOnly; Secure; SameSite=Strict`, sin `Expires`). Las peticiones posteriores **no** incluyen `Set-Cookie: __Host-sf_session`. En la base de datos, el valor de la cookie **no aparece** (sí `v1$<hex>`) y `last_activity_at` avanza | US1-5, R2, TS-SC15/16 |
| V6 | Login con usuario inexistente / contraseña errónea | `401` idénticos | US1-6 |
| V7 | Cliente A sobre `/users/<id_B>/profile` y `/users/<id_B>/sessions` | `404`; evento `authz_denied` | US2-2 |
| V8 | Cliente sobre `/admin/users` y `/audit/events` | `403` | US2-3 |
| V9 | Administrador sobre `/audit/events` | `403` | US2-5 |
| V10 | Activación desde Mailpit: abrir `/activate#token=…` | La barra de direcciones pierde el fragmento al cargar. Después, login → `mfa_enrollment_required`; rutas protegidas → `401` hasta confirmar el TOTP | US3-9, R7 |
| V11 | Código TOTP repetido | `401` | US3-4 |
| V12 | Código de recuperación (28 caracteres) usado dos veces | `200` con `recovery_codes_remaining: 9`; después `401` | US3-5/6 |
| V13 | 7 logins fallidos seguidos y uno correcto inmediato | Rechazos sin evaluar desde el 6.º; el correcto también, durante el retraso; evento `throttle_account_delay` | US5 |
| V14 | Recuperación desde `/forgot-password` (o `POST /auth/password-reset/request`) para una cuenta existente e inexistente; después `/reset#token=…` (`confirm`) | Dos `202` idénticos; correo en Mailpit en pocos segundos; `204`; las sesiones previas dan `401`; reutilizar el token → `400`; un token usado pasados **15 minutos** desde su emisión → `400` (en las pruebas automatizadas, con reloj simulado: TS-I11) | US7 |
| V15 | Reinicio de MFA: el titular hace login con contraseña y pulsa "perdí mi dispositivo" → el Administrador abre el caso con el canal → el titular lee el código → el Administrador autoriza con su TOTP | `authorized`; notificación en Mailpit; sesiones del titular revocadas; el titular necesita contraseña y alta nueva; evento con solicitante, autorizador, fechas y método | US4-6/7, R11 |
| V16 | El Administrador intenta abrir un caso propio; cuarto intento de código; código reutilizado | `403`; `cancelled` al tercer fallo; `409` | FR-020, R11 |
| V17 | El Auditor filtra `event_type=login_failed` | Solo esos eventos, sin secretos | US6 |
| V18 | Revocación inmediata: el Cliente cierra su otra sesión con `DELETE /users/me/sessions/{public_id}` | La otra cookie da `401` en la siguiente petición | FR-010, R2 |

La colección Postman equivalente se guarda como evidencia (Principio V).

## 6. Pruebas automatizadas

Los mismos trabajos que la CI (R16):

```bash
docker compose run --rm backend pytest -m unit
docker compose run --rm backend pytest -m "integration or session_conformance or security or contract or acceptance" -m "not stack" --cov
docker compose run --rm backend pytest -m stack                   # con el stack levantado y sano
npx --prefix frontend playwright test                             # TS-E01–E03 y TS-S24
```

**Resultado esperado**: todo en verde y ninguna prueba omitida por falta de infraestructura (las
pruebas `stack` y `e2e` **fallan** si el stack no responde). La suite de conformidad del motor de
sesión (TS-SC01–SC20) es **obligatoria antes de actualizar Django**. Las E2E no generan trazas,
vídeos ni capturas, no se suben como artefactos y obtienen los tokens con el *fixture* autenticado
de Mailpit (T139). Exporta `MAILPIT_API_USER` y `MAILPIT_API_PASSWORD` antes de ejecutarlas. Las E2E se reparten por
historia: TS-E01 (registro y login), TS-E02 (activación) y TS-E03 (recuperación).

## 7. DevSecOps (igual que en CI)

```bash
semgrep ci --config p/django --config p/python --config p/react --config p/secrets --config .semgrep/
bandit -r backend/ -ll
pip-audit -r backend/requirements.txt --require-hashes
npm audit --omit=dev --prefix frontend
trivy image securefin-backend:lab && trivy fs --scanners misconfig,secret .
```

**Resultado esperado**: 0 hallazgos altos o críticos sin justificar.

## 8. Calibración de Argon2id y rendimiento (R4)

1. **Coste aislado** (dentro de la imagen del backend):
   ```bash
   docker compose run --rm backend python -m argon2 -t 3 -m 65536 -p 1 -n 100
   docker compose run --rm backend /usr/bin/time -v python -m argon2 -t 3 -m 65536 -p 1 -n 1
   ```
   Registrar la latencia media y el RSS máximo.
2. **Carga del endpoint**, con 20 cuentas ficticias distintas y concurrencias 1, 5, 10 y 20:
   ```bash
   ab -n 400 -c 20 -p login.json -T application/json \
      -H "X-CSRFToken: $CSRF" -H "Origin: https://securefin.local" -C "<cookies>" $B/auth/login
   ```
   Registrar p50, p95, p99 y errores.
3. **Recursos**: `docker stats --no-stream backend` durante el paso 2 (CPU y memoria máximas).
4. Anotar los resultados en la tabla de R4 (fecha y equipo).

**Criterio**: p95 inferior a 2 s con concurrencia 20 (SC-010). Si no se cumple, ajustar primero los
workers o los recursos; reducir parámetros exige justificación y aprobación, y nunca por debajo del
mínimo de OWASP.

## 9. Inspección de secretos (SC-003)

`pytest -m security -k secrets_scan` busca, tras ejecutar las suites, contraseñas, tokens, códigos,
**valores de cookie de sesión** y secretos TOTP en la base de datos, en el outbox, en los logs de
Django y de Nginx y en las sentencias SQL capturadas. **Resultado esperado**: 0 coincidencias en
claro.
