#!/usr/bin/env bash
# Prueba de humo del stack levantado: comprueba DESDE FUERA, como lo vería un atacante, que los
# controles de seguridad responden. La usa el CI (trabajo `stack`) y se puede correr en local:
#   bash scripts/smoke-stack.sh
# Sale con código 1 si algún control falla.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

HOST=securefin.local
BASE="https://$HOST"
CA=secrets/lab_ca.pem
RES=()
getent hosts "$HOST" >/dev/null 2>&1 || ping -n 1 -w 500 "$HOST" >/dev/null 2>&1 \
  || RES=(--resolve "$HOST:443:127.0.0.1" --resolve "$HOST:80:127.0.0.1")
TLS=(--cacert "$CA" --ssl-no-revoke)
curl --help all 2>/dev/null | grep -q -- "--ssl-no-revoke" || TLS=(--cacert "$CA")
C=(curl -s "${RES[@]}" "${TLS[@]}")
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT

fails=0
check() { # check "<descripción>" <condición evaluada por test/[[ ]]>
  local desc="$1"; shift
  if "$@"; then printf '  \033[32m✔\033[0m %s\n' "$desc"; else printf '  \033[31m✘\033[0m %s\n' "$desc"; fails=$((fails + 1)); fi
}
has() { grep -qiE "$1" <<<"$2"; }

echo "== Semanas 2 y 5: TLS, redirección, cabeceras y banner"
H="$("${C[@]}" -I "$BASE/" | tr -d '\r')"
check "HTTPS responde 200 con certificado de la CA del laboratorio" has '^HTTP/[0-9.]+ 200' "$H"
check "Server: nginx sin número de versión (server_tokens off)" has '^server: nginx$' "$H"
check "X-Frame-Options: DENY (clickjacking)" has '^x-frame-options: DENY' "$H"
check "X-Content-Type-Options: nosniff" has '^x-content-type-options: nosniff' "$H"
check "Content-Security-Policy con script-src 'self' (XSS)" has "^content-security-policy: .*script-src 'self'" "$H"
check "Strict-Transport-Security (HSTS)" has '^strict-transport-security: max-age=' "$H"
R="$(curl -s "${RES[@]}" -I "http://$HOST/" | tr -d '\r')"
check "HTTP plano solo redirige 301 a HTTPS" has '^HTTP/[0-9.]+ 301' "$R"
T="$("${C[@]}" -I -X TRACE "$BASE/" | head -1)"
check "TRACE bloqueado (405)" has ' 405' "$T"
if command -v openssl >/dev/null; then
  O="$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$HOST" -tls1_1 2>&1 || true)"
  check "TLS 1.1 rechazado" bash -c '! grep -qE "^New, TLSv1(\.1)?," <<<"$0"' "$O"
fi

echo "== Semana 8: inyección SQL en el login"
"${C[@]}" -c "$JAR" -b "$JAR" -o /dev/null "$BASE/api/v1/auth/csrf"
TOK="$(grep -oE '__Host-sf_csrftoken[[:space:]]+[^[:space:]]+' "$JAR" | awk '{print $2}')"
login() {
  "${C[@]}" -c "$JAR" -b "$JAR" -w '|%{http_code}' -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' -H "Origin: $BASE" -H "X-CSRFToken: $TOK" \
    --data "{\"email\":\"$1\",\"password\":\"x\"}"
}
CTRL="$(login "smoke-$RANDOM@lab.securefin.local")"
INJ="$(login "' OR 1=1 --")"
check "' OR 1=1 -- → 401 (no inicia sesión ni da 500)" has '\|401$' "$INJ"
check "Respuesta idéntica a un login fallido normal" test "$INJ" = "$CTRL"

echo "== Semanas 9 y 10: rate limiting en Nginx"
CODES="$(for _ in $(seq 1 60); do "${C[@]}" -o /dev/null -w '%{http_code}\n' "$BASE/api/v1/auth/csrf" & done; wait)"
N429="$(grep -c '^429$' <<<"$CODES")"; N5XX="$(grep -c '^5' <<<"$CODES")"
check "Ráfaga de 60 peticiones → $N429 respuestas 429" test "$N429" -gt 0
check "Ninguna respuesta 5xx durante la ráfaga ($N5XX)" test "$N5XX" -eq 0

echo
if [ "$fails" -eq 0 ]; then echo "Todos los controles respondieron correctamente."; else echo "$fails control(es) fallaron."; fi
exit $((fails > 0))
