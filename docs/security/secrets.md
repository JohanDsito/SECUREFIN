# Gestión de secretos del laboratorio

**Referencias**: constitución, Principio III; research R8, R10; tareas T012, T027.

Los secretos viven solo en archivos dentro de `secrets/` (ignorado por git) y se montan como
secretos de Docker Compose en `/run/secrets`. Nunca se escriben en el repositorio, en imágenes, en
la base de datos ni en los logs.

## Una clave por propósito

| Archivo | Uso | Rotación |
|---|---|---|
| `django_secret_key` | Firma de Django (datos de sesión, CSRF) | Manual |
| `session_hmac_key_vN` | Verificadores HMAC de los identificadores de sesión | `SESSION_HMAC_KEY_VERSIONS` + `iam_rotate_session_key` |
| `token_hmac_key_vN` | Verificadores HMAC de los tokens de un solo uso | `TOKEN_HMAC_KEY_VERSIONS` |
| `throttle_hmac_key_vN` | Resúmenes seudonimizados de la limitación por cuenta | `THROTTLE_HMAC_KEY_VERSIONS` |
| `totp_key_vN` | AES-256-GCM de los secretos TOTP (exactamente 32 bytes) | `TOTP_KEY_VERSIONS` + `iam_rotate_totp_key` |
| `db_superuser_password` | Superusuario `postgres` (solo inicialización del contenedor) | Manual |
| `db_owner_password` | Rol `securefin_owner` (solo el servicio `migrate`) | Manual |
| `db_app_password` | Rol `securefin_app` (backend y mailer) | Manual |
| `tls_cert.pem`, `tls_key.pem` | Certificado TLS de laboratorio (SAN `securefin.local` e `127.0.0.1`) | Manual |
| `mailpit_htpasswd` | **Una sola** credencial Basic para el proxy de Mailpit en Nginx **y** para Mailpit | Manual |

El backend no arranca si falta una clave, si mide menos de 32 bytes o si dos claves coinciden
(T027).

## Generación (Git Bash o Linux)

```bash
mkdir -p secrets && chmod 700 secrets
for k in django_secret_key session_hmac_key_v1 token_hmac_key_v1 throttle_hmac_key_v1 \
         totp_key_v1 db_superuser_password db_owner_password db_app_password; do
  # tr elimina CR/LF: el openssl de Git Bash escribe CRLF y un "\r" final cambiaría la contraseña
  openssl rand -base64 32 | tr -d '\r\n' > "secrets/$k"
done

# CA de laboratorio y certificado con SAN para securefin.local y 127.0.0.1
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -keyout secrets/lab_ca.key -out secrets/lab_ca.pem -subj "/CN=SecureFin Lab CA"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout secrets/tls_key.pem \
  -out secrets/tls.csr -subj "/CN=securefin.local"
printf "subjectAltName=DNS:securefin.local,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > secrets/san.ext
openssl x509 -req -in secrets/tls.csr -CA secrets/lab_ca.pem -CAkey secrets/lab_ca.key \
  -CAcreateserial -days 365 -sha256 -extfile secrets/san.ext -out secrets/tls_cert.pem

# Credencial ÚNICA de Mailpit (apr1, admitido por Nginx y por Mailpit)
MP_USER=labmail
MP_PASS="$(openssl rand -hex 18)"
printf "%s:%s\n" "$MP_USER" "$(openssl passwd -apr1 "$MP_PASS" | tr -d '\r\n')" > secrets/mailpit_htpasswd
echo "Guarda la contraseña de Mailpit en tu gestor de contraseñas; no se escribe en ningún archivo."
```

## Por qué una sola credencial para Mailpit

Una petición HTTP solo lleva una cabecera `Authorization: Basic`. Nginx la valida con
`mailpit_htpasswd` y la reenvía a Mailpit, que la valida otra vez con el mismo archivo
(`MP_UI_AUTH_FILE`). Es defensa en profundidad ante un fallo de configuración de una de las dos
capas, no dos credenciales distintas. Si la credencial se filtra, se abren ambas capas: se
regenera el archivo y se reinician los dos servicios.

## En CI

El trabajo `stack` genera todos estos archivos de forma **efímera** con OpenSSL en el runner, los
usa y los borra al terminar (`if: always()`). Nunca se usan secretos reales ni secretos de GitHub.
