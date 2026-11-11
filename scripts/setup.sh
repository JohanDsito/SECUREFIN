#!/usr/bin/env bash
# SecureFin — preparación del laboratorio en un solo paso (Git Bash en Windows, Linux o macOS).
#   bash scripts/setup.sh            genera secretos (si faltan) y levanta el stack completo
#   bash scripts/setup.sh secretos   solo genera los secretos
#   bash scripts/setup.sh arrancar   solo levanta el stack (db → migraciones → resto)
#   bash scripts/setup.sh pentest    levanta además OWASP Juice Shop (Semana 8, 127.0.0.1:3000)
#   bash scripts/setup.sh mailpit    nueva contraseña del buzón Mailpit (si la olvidaste)
#   bash scripts/setup.sh parar      detiene todo (conserva la base de datos)
#   bash scripts/setup.sh reset      detiene todo y BORRA volúmenes y secretos (empezar de cero)
# Nada de lo generado se versiona: secrets/ está en .gitignore (Semana 1 / Principio III).
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }
COMPOSE=(docker compose -f infra/compose.yaml)

ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
info() { printf '\033[1;36m» %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }

secretos() {
  if [[ -f secrets/tls_cert.pem && -f secrets/mailpit_htpasswd ]]; then
    ok "secrets/ ya existe: no se regenera (usa 'reset' para empezar de cero)"
    return
  fi
  info "Semana 1 — Generando claves aleatorias de 256 bits (una por propósito)"
  mkdir -p secrets secrets/pki-public && chmod 700 secrets
  for k in django_secret_key session_hmac_key_v1 token_hmac_key_v1 throttle_hmac_key_v1 \
           db_superuser_password db_owner_password db_app_password; do
    openssl rand -base64 32 | tr -d '\r\n' > "secrets/$k"
  done
  # AES-256-GCM necesita exactamente 32 bytes: 64 caracteres hex o base64 de 32 bytes
  openssl rand -base64 32 | tr -d '\r\n' > secrets/totp_key_v1

  info "Semana 1/2 — PKI del laboratorio: CA RSA-3072 + certificado del servidor (SAN securefin.local)"
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
    -keyout secrets/lab_ca.key -out secrets/lab_ca.pem -subj "/CN=SecureFin Lab CA" 2>/dev/null
  MSYS_NO_PATHCONV=1 openssl req -newkey rsa:3072 -sha256 -nodes -keyout secrets/tls_key.pem \
    -out secrets/tls.csr -subj "/CN=securefin.local" 2>/dev/null
  printf "subjectAltName=DNS:securefin.local,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > secrets/san.ext
  openssl x509 -req -in secrets/tls.csr -CA secrets/lab_ca.pem -CAkey secrets/lab_ca.key \
    -CAcreateserial -days 365 -sha256 -extfile secrets/san.ext -out secrets/tls_cert.pem 2>/dev/null
  cp secrets/lab_ca.pem secrets/pki-public/lab_ca.pem   # solo la parte PÚBLICA de la CA

  mailpit_cred
  ok "Secretos creados en secrets/ (ignorado por git)"
}

mailpit_cred() {
  info "Credencial del buzón de laboratorio (Mailpit, hash apr1)"
  local mp_pass; mp_pass="$(openssl rand -hex 12)"
  printf "labmail:%s\n" "$(openssl passwd -apr1 "$mp_pass" | tr -d '\r\n')" > secrets/mailpit_htpasswd
  echo
  printf '\033[1;35m  Buzón Mailpit → https://127.0.0.1:8025   usuario: labmail   contraseña: %s\033[0m\n' "$mp_pass"
  warn "Anota esa contraseña AHORA: no se guarda en claro en ningún archivo."
  echo
}

hosts() {
  local f=/etc/hosts
  [[ -f /c/Windows/System32/drivers/etc/hosts ]] && f=/c/Windows/System32/drivers/etc/hosts
  if grep -qE '^\s*127\.0\.0\.1\s+securefin\.local' "$f" 2>/dev/null; then
    ok "securefin.local ya apunta a 127.0.0.1 en $f"
  else
    warn "Falta la línea '127.0.0.1 securefin.local' en $f"
    warn "Windows: abre PowerShell COMO ADMINISTRADOR y ejecuta:"
    echo '    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "127.0.0.1 securefin.local"'
  fi
}

arrancar() {
  info "Base de datos"
  "${COMPOSE[@]}" up -d --build --wait db
  info "Migraciones (único servicio con la credencial del propietario de la BD)"
  "${COMPOSE[@]}" --profile oneoff run --rm migrate
  info "Resto del stack (backend, mailer, mailpit, nginx) — la primera vez tarda varios minutos"
  "${COMPOSE[@]}" up -d --build --wait
  "${COMPOSE[@]}" ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
  ok "Stack listo → https://securefin.local"
}

case "${1:-todo}" in
  secretos) secretos ;;
  arrancar) arrancar ;;
  pentest)
    info "Semana 8 — OWASP Juice Shop (app VULNERABLE a propósito; solo en 127.0.0.1:3000)"
    "${COMPOSE[@]}" --profile pentest up -d juiceshop
    ok "Juice Shop → http://127.0.0.1:3000" ;;
  mailpit)
    mailpit_cred
    "${COMPOSE[@]}" up -d --force-recreate nginx mailpit ;;
  parar) "${COMPOSE[@]}" --profile pentest down ;;
  reset)
    "${COMPOSE[@]}" --profile pentest --profile oneoff down -v --remove-orphans || true
    rm -rf secrets
    ok "Todo borrado. Vuelve a ejecutar: bash scripts/setup.sh" ;;
  todo) secretos; hosts; arrancar ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
