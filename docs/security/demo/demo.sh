#!/usr/bin/env bash
# Demo en vivo de SecureFin Gateway (Git Bash en Windows, con el stack levantado).
#   bash docs/security/demo/demo.sh <tema>
# Temas: estado cabeceras tls cripto red privilegios nmap sqli dos fuerzabruta auditoria trivy todo
# Solo usa credenciales FICTICIAS. No imprime cookies, tokens ni contraseñas reales.
set -u
cd "$(dirname "$0")/../../.." || exit 1
# docker necesita MSYS_NO_PATHCONV=1 en Git Bash; curl y openssl, NO (usan rutas /tmp convertidas)
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }

B="https://securefin.local/api/v1"
CURL=(curl -sk --ssl-no-revoke)
JAR="$(mktemp)"; trap 'rm -f "$JAR" /tmp/sf-demo.*' EXIT

title() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
note()  { printf '\033[0;33m→ %s\033[0m\n' "$*"; }
psql_ro() { docker exec securefin-db-1 psql -U postgres -d securefin -At -F ' | ' -c "SET search_path=securefin,public;" -c "$1" | grep -v '^SET$'; }
csrf() { "${CURL[@]}" -b "$JAR" -c "$JAR" -o /dev/null "$B/auth/csrf"; grep -oE "__Host-sf_csrftoken\s+\S+" "$JAR" | awk '{print $2}'; }
post() { # post <ruta> <json> → imprime "código cuerpo"
  local tok; tok=$(csrf)
  "${CURL[@]}" -b "$JAR" -c "$JAR" -o /tmp/sf-demo.body -D /tmp/sf-demo.head -w "%{http_code}" -X POST "$B$1" \
    -H "Content-Type: application/json" -H "Origin: https://securefin.local" -H "X-CSRFToken: $tok" --data "$2"
  printf '  %s\n' "$(head -c 150 /tmp/sf-demo.body)"
}

estado() {
  title "Stack: contenedores y salud"
  docker compose -f infra/compose.yaml ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
}

cabeceras() {
  title "Semana 5 — Banner grabbing y cabeceras defensivas"
  "${CURL[@]}" -I https://securefin.local/ | tr -d '\r' | grep -E "^HTTP|^Server|X-Frame|X-Content|Strict-Transport|Content-Security|Referrer|Cache-Control"
  note "Server: nginx SIN versión (server_tokens off)"
  title "HTTP plano solo redirige a HTTPS"
  curl -s -I http://securefin.local/ | tr -d '\r' | grep -E "^HTTP|^Location"
  title "Métodos peligrosos bloqueados (TRACE)"
  "${CURL[@]}" -I -X TRACE https://securefin.local/ | tr -d '\r' | head -1
}

tls() {
  title "Semana 2 — Versiones de TLS"
  for v in -tls1_3 -tls1_2 "-tls1_1 -cipher DEFAULT@SECLEVEL=0"; do
    printf '%-12s ' "${v%% *}"
    echo | openssl s_client -connect 127.0.0.1:443 -servername securefin.local $v 2>&1 | grep -m1 -E "^New,|alert protocol version" || true
  done
  note "TLS 1.0/1.1 rechazados (ssl_protocols TLSv1.2 TLSv1.3)"
  title "Certificado del servidor"
  echo | openssl s_client -connect 127.0.0.1:443 -servername securefin.local 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null
  echo | openssl s_client -connect 127.0.0.1:443 -servername securefin.local 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -m1 "Public-Key"
}

cripto() {
  title "Semana 1 — Hash, salt, AES, RSA y ECC con OpenSSL"
  local d; d=$(mktemp -d)
  printf 'saldo: 1.000.000 COP' > "$d/claro.txt"
  echo "SHA-256 de 'SecureFin' (dos veces: mismo hash → por eso hace falta salt):"
  printf SecureFin | openssl dgst -sha256; printf SecureFin | openssl dgst -sha256
  echo "Con salt aleatoria (cambia en cada ejecución):"
  s=$(openssl rand -hex 8); printf '%s' "${s}SecureFin" | openssl dgst -sha256 | sed "s/^/salt=$s → /"
  echo "AES-256 (simétrico): cifrar y descifrar"
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$d/claro.txt" -out "$d/c.bin" -pass pass:demo-clase
  echo "  cifrado (hex): $(od -An -tx1 "$d/c.bin" | tr -d ' \n' | head -c 64)…"
  echo "  descifrado: $(openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$d/c.bin" -pass pass:demo-clase)"
  echo "RSA-3072 (asimétrico): cifra la pública, descifra la privada"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$d/k.pem" 2>/dev/null
  openssl pkey -in "$d/k.pem" -pubout -out "$d/p.pem"
  openssl pkeyutl -encrypt -pubin -inkey "$d/p.pem" -pkeyopt rsa_padding_mode:oaep -in "$d/claro.txt" -out "$d/r.bin"
  echo "  descifrado: $(openssl pkeyutl -decrypt -inkey "$d/k.pem" -pkeyopt rsa_padding_mode:oaep -in "$d/r.bin")"
  echo "ECC P-256: firma digital"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$d/e.pem" 2>/dev/null
  openssl pkey -in "$d/e.pem" -pubout -out "$d/ep.pem"
  openssl dgst -sha256 -sign "$d/e.pem" -out "$d/f.bin" "$d/claro.txt"
  echo "  $(openssl dgst -sha256 -verify "$d/ep.pem" -signature "$d/f.bin" "$d/claro.txt")"
  rm -rf "$d"
  title "Así guarda SecureFin las contraseñas (salt y hash ocultos)"
  psql_ro "SELECT f || '\$<salt>\$<hash>  → ' || count(*) || ' usuarios' FROM (SELECT split_part(password,'\$',1)||'\$'||split_part(password,'\$',2)||'\$'||split_part(password,'\$',3)||'\$'||split_part(password,'\$',4) AS f FROM iam_user WHERE password LIKE 'argon2%') s GROUP BY f;"
}

red() {
  title "Semanas 3 y 6 — Zonas de red (VLAN/DMZ) y denegar por defecto"
  for n in $(docker network ls --format '{{.Name}}' | grep '^securefin_'); do
    printf '%-20s internal=%-5s %s\n' "$n" "$(docker network inspect -f '{{.Internal}}' "$n")" "$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$n")"
  done
  t() { docker run --rm --network "$1" busybox:1.37 sh -c "nc -z -w 2 $2 $3 && echo ALCANZABLE || echo BLOQUEADO" 2>/dev/null | tail -1; }
  echo "DMZ (edge_net) → base de datos db:5432 : $(t securefin_edge_net db 5432)"
  echo "DMZ (edge_net) → backend:8000         : $(t securefin_edge_net backend 8000)"
  echo "app_net        → backend:8000         : $(t securefin_app_net backend 8000)"
  echo "data_net       → db:5432              : $(t securefin_data_net db 5432)"
  echo "backend        → Internet             : $(docker exec securefin-backend-1 python -c "import socket;socket.create_connection(('1.1.1.1',443),3);print('ALCANZABLE')" 2>/dev/null || echo BLOQUEADO)"
}

privilegios() {
  title "Semana 4 — Mínimo privilegio en PostgreSQL (solo lectura de permisos)"
  psql_ro "SELECT 'app sobre auditoría: INSERT='||has_table_privilege('securefin_app','audit_securityevent','INSERT')||' UPDATE='||has_table_privilege('securefin_app','audit_securityevent','UPDATE')||' DELETE='||has_table_privilege('securefin_app','audit_securityevent','DELETE')||' TRUNCATE='||has_table_privilege('securefin_app','audit_securityevent','TRUNCATE');"
  psql_ro "SELECT 'app puede crear tablas: '||has_schema_privilege('securefin_app','securefin','CREATE');"
  psql_ro "SELECT 'dueño de las tablas (único que puede DROP): '||string_agg(DISTINCT tableowner, ', ') FROM pg_tables WHERE schemaname='securefin';"
  psql_ro "SELECT 'triggers append-only: '||string_agg(tgname, ', ') FROM pg_trigger WHERE tgrelid='securefin.audit_securityevent'::regclass AND NOT tgisinternal;"
}

nmap() {
  title "Semana 8 — Reconocimiento con Nmap (-sV y scripts vuln) sobre los puertos del laboratorio"
  docker run --rm instrumentisto/nmap:7.95 -sV -Pn -p 80,443,1025,8000,8025 --script vuln host.docker.internal 2>&1 \
    | grep -E "^[0-9]+/tcp|VULNERABLE|Couldn't find|State:"
  note "Solo 80/443 (y 8025 en loopback); 8000 y 1025 cerrados: backend y correo no son alcanzables"
}

sqli() {
  title "Semana 8 — Inyección SQL"
  for p in "' OR 1=1 --" "admin@lab.securefin.local' --" "x' UNION SELECT password FROM iam_user --" "x'; DROP TABLE iam_user; --"; do
    printf 'email=%-45s → ' "$p"; post /auth/login "{\"email\":\"${p//\"/\\\"}\",\"password\":\"x\"}"
  done
  printf '%-52s → ' "registro con \"role\":\"admin\" (asignación masiva)"
  post /auth/register '{"email":"demo-sqli@lab.securefin.local","name":"Demo","password":"una frase larga de prueba 2026","role":"admin"}'
  echo "Usuarios en la tabla tras el DROP TABLE: $(psql_ro 'SELECT count(*) FROM iam_user;')"
}

dos() {
  title "Semanas 9 y 10 — Inundación HTTP (Apache Benchmark) contra Nginx"
  note "Mientras corre, recarga https://securefin.local en el navegador: sigue respondiendo"
  docker run --rm --network securefin_edge_net httpd:2.4-alpine ab -r -n 3000 -c 100 https://nginx/ 2>&1 \
    | grep -E "Complete requests|Non-2xx|Requests per second|Time taken"
  echo "Respuestas de Nginx en el último minuto:"
  docker logs --since 1m securefin-nginx-1 2>/dev/null | grep -oE '" [0-9]{3} ' | sort | uniq -c | sed 's/"//g'
  note "429 = petición descartada por limit_req/limit_conn ANTES de llegar a Django"
}

fuerzabruta() {
  title "Semana 10 — Fuerza bruta contra una cuenta (por cuenta: retrasos desde el 5.º fallo; por IP: 20/min)"
  local victim="victima-$(date +%s)@lab.securefin.local"   # cuenta distinta en cada ejecución
  for i in $(seq 1 23); do
    code=$(post /auth/login "{\"email\":\"$victim\",\"password\":\"intento-$i\"}" | head -1 | cut -c1-3)
    ra=$(grep -i '^Retry-After' /tmp/sf-demo.head | tr -d '\r' | awk '{print $2}')
    printf 'intento %2d → %s%s\n' "$i" "$code" "${ra:+  Retry-After: ${ra}s}"
    sleep 0.3
  done
  echo "Qué pasó por dentro (auditoría del último minuto; las respuestas 401 son idénticas a propósito):"
  psql_ro "SELECT '  login_failed reason=' || coalesce(metadata->>'reason','-') || ' → ' || count(*) FROM audit_securityevent WHERE event_type='login_failed' AND occurred_at > now() - interval '1 minute' GROUP BY metadata->>'reason';"
  psql_ro "SELECT '  throttle_account_delay → ' || count(*) || ' (retraso aplicado: ' || coalesce(max((metadata->>'delay_seconds')::int),0) || ' s)' FROM audit_securityevent WHERE event_type='throttle_account_delay' AND occurred_at > now() - interval '1 minute';"
  note "invalid_credentials = contraseña evaluada (máx. 5); throttled = rechazado SIN evaluar; 429 = límite por IP"
}

auditoria() {
  title "Semana 4 — Auditoría: eventos de seguridad (sin datos personales)"
  psql_ro "SELECT event_type, outcome, count(*) FROM audit_securityevent GROUP BY 1,2 ORDER BY 3 DESC LIMIT 15;"
  title "Últimos 8 eventos"
  psql_ro "SELECT to_char(occurred_at,'HH24:MI:SS'), event_type, outcome, coalesce(actor_role,'-'), coalesce(metadata->>'scope', metadata->>'reason', '') FROM audit_securityevent ORDER BY occurred_at DESC LIMIT 8;"
}

trivy() {
  title "Semana 7 — Trivy: CVE HIGH/CRITICAL en las imágenes"
  for img in securefin-nginx:lab securefin-backend:lab; do
    printf '%-24s ' "$img"
    docker run --rm -v securefin-trivy-cache:/root/.cache/ -v //var/run/docker.sock:/var/run/docker.sock:ro \
      aquasec/trivy:0.70.0 image --quiet --severity HIGH,CRITICAL "$img" 2>/dev/null | grep -m1 -E "^Total:" || echo "Total: 0"
  done
  note "Backend: las restantes no tienen parche publicado por Debian (ver evidence/E8)"
}

case "${1:-}" in
  estado|cabeceras|tls|cripto|red|privilegios|nmap|sqli|dos|fuerzabruta|auditoria|trivy) "$1" ;;
  todo) estado; cabeceras; tls; cripto; red; privilegios; sqli; auditoria ;;
  *) echo "Uso: bash docs/security/demo/demo.sh <estado|cabeceras|tls|cripto|red|privilegios|nmap|sqli|dos|fuerzabruta|auditoria|trivy|todo>"; exit 1 ;;
esac
