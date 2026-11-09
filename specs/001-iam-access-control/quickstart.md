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
for k in django_secret_key session_hmac_key_v1 token_hmac_key_v1 totp_key_v1 \
         db_owner_password db_app_password; do
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
Mailpit (`http://127.0.0.1:8025`, a través de Nginx, con doble autenticación). Repetir el bootstrap
falla porque ya existe un Administrador.

## 4. Comprobaciones de infraestructura (TS-S10, TS-S11, TS-S25, TS-S26)

| Comprobación | Cómo | Esperado |
|---|---|---|
| Solo Nginx publica puertos | `docker compose config` | Nginx: `443`, `80` y `127.0.0.1:8025`. `mailpit`, `db`, `backend` y `mailer`: sin `ports` |
| Redes | `docker network inspect` | `app_net`, `data_net` y `mail_net` con `Internal: true`. Mailpit solo en `mail_net`. El backend web no comparte red con Mailpit; `mailer` y Mailpit solo comparten `mail_net`. Nginx no está en `data_net` |
| Exposición externa | Desde otra máquina: `nmap -p 25,1025,5432,8000,8025 <ip_host>` | Todos cerrados o filtrados; solo `80` y `443` abiertos |
| Interfaz de Mailpit | `curl -I http://127.0.0.1:8025` sin credenciales / solo con las de Nginx | `401` en ambos casos; con las dos credenciales, `200` |
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
| V1 | Registro con contraseña de 15 caracteres o más | `201`; `password` empieza por `$argon2id$v=19$m=65536,t=3,p=1` | US1-1 |
| V2 | Registro con `"role": "admin"` | `400` | US1-2 |
| V3 | Contraseña de 14 caracteres / `securefin-gateway-2026` | `400` con la regla incumplida | US1-3 |
| V4 | POST sin `X-CSRFToken` | `403` | R3 |
| V5 | Login correcto | `200`; cookie `__Host-sf_session` con `HttpOnly; Secure; SameSite=Strict`. En la base de datos, el valor de la cookie **no aparece** (sí `v1$<hex>`) | US1-5, R2 |
| V6 | Login con usuario inexistente / contraseña errónea | `401` idénticos | US1-6 |
| V7 | Cliente A sobre `/users/<id_B>/profile` y `/users/<id_B>/sessions` | `404`; evento `authz_denied` | US2-2 |
| V8 | Cliente sobre `/admin/users` y `/audit/events` | `403` | US2-3 |
| V9 | Administrador sobre `/audit/events` | `403` | US2-5 |
| V10 | Activación desde Mailpit: abrir `/activate#token=…` | La barra de direcciones pierde el fragmento al cargar. Después, login → `mfa_enrollment_required`; rutas protegidas → `401` hasta confirmar el TOTP | US3-9, R7 |
| V11 | Código TOTP repetido | `401` | US3-4 |
| V12 | Código de recuperación (28 caracteres) usado dos veces | `200` con `recovery_codes_remaining: 9`; después `401` | US3-5/6 |
| V13 | 7 logins fallidos seguidos y uno correcto inmediato | Rechazos sin evaluar desde el 6.º; el correcto también, durante el retraso; evento `throttle_account_delay` | US5 |
| V14 | Recuperación para una cuenta existente e inexistente; después `confirm` | Dos `202` idénticos; correo en Mailpit en pocos segundos; `204`; las sesiones previas dan `401`; reutilizar el token → `400` | US7 |
| V15 | Reinicio de MFA: el titular hace login con contraseña y pulsa "perdí mi dispositivo" → el Administrador abre el caso con el canal → el titular lee el código → el Administrador autoriza con su TOTP | `authorized`; notificación en Mailpit; sesiones del titular revocadas; el titular necesita contraseña y alta nueva; evento con solicitante, autorizador, fechas y método | US4-6/7, R11 |
| V16 | El Administrador intenta abrir un caso propio; cuarto intento de código; código reutilizado | `403`; `cancelled` al tercer fallo; `409` | FR-020, R11 |
| V17 | El Auditor filtra `event_type=login_failed` | Solo esos eventos, sin secretos | US6 |
| V18 | Revocación inmediata: el Cliente cierra su otra sesión con `DELETE /users/me/sessions/{public_id}` | La otra cookie da `401` en la siguiente petición | FR-010, R2 |

La colección Postman equivalente se guarda como evidencia (Principio V).

## 6. Pruebas automatizadas

```bash
docker compose run --rm backend pytest -m "unit or integration"
docker compose run --rm backend pytest -m session_conformance     # TS-SC01–SC14
docker compose run --rm backend pytest -m security                # TS-S
docker compose run --rm backend pytest -m "contract or acceptance" --cov
```

**Resultado esperado**: todo en verde. La suite de conformidad del motor de sesión es **obligatoria
antes de actualizar Django**.

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
