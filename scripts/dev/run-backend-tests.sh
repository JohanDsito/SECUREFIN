#!/usr/bin/env bash
# Ejecuta las pruebas del backend en contenedores desechables (Git Bash en Windows, Linux o macOS).
#   bash scripts/dev/run-backend-tests.sh                         suite completa (sin las de stack)
#   bash scripts/dev/run-backend-tests.sh tests/security -q       argumentos que se pasan a pytest
#   bash scripts/dev/run-backend-tests.sh --rebuild ...           reconstruye la imagen antes
#   bash scripts/dev/run-backend-tests.sh --stop                  borra el PostgreSQL de pruebas
#
# - Imagen securefin-test-runner:local (scripts/dev/test-runner.Dockerfile): se construye sola la
#   primera vez; usa --rebuild si cambian backend/requirements*.txt.
# - PostgreSQL 17 efímero en la red securefin-devtest, con el rol securefin_app. Las contraseñas se
#   generan al crear el contenedor y se guardan solo en su entorno: no hay secretos en el repositorio.
# - El código se monta en solo lectura; la cobertura se escribe en /tmp del contenedor.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }

IMAGE=securefin-test-runner:local
NET=securefin-devtest
PG=securefin-devtest-pg
PG_IMAGE=postgres:17@sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f

if [[ "${1:-}" == "--stop" ]]; then
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "PostgreSQL de pruebas eliminado."
  exit 0
fi

if [[ "${1:-}" == "--rebuild" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  [[ "${1:-}" == "--rebuild" ]] && shift
  echo "» Construyendo $IMAGE (solo la primera vez o con --rebuild)"
  docker build -q -t "$IMAGE" -f scripts/dev/test-runner.Dockerfile . >/dev/null
fi

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
if ! docker ps --format '{{.Names}}' | grep -qx "$PG"; then
  docker rm -f "$PG" >/dev/null 2>&1 || true
  pg_pw="$(openssl rand -hex 16)"
  app_pw="$(openssl rand -hex 16)"
  echo "» Arrancando PostgreSQL de pruebas ($PG)"
  docker run -d --name "$PG" --network "$NET" -e POSTGRES_PASSWORD="$pg_pw" -e SF_APP_PASSWORD="$app_pw" \
    "$PG_IMAGE" >/dev/null
  for _ in $(seq 1 60); do docker exec "$PG" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
  sleep 2
  docker exec "$PG" psql -U postgres -v ON_ERROR_STOP=1 -q \
    -c "CREATE ROLE securefin_app LOGIN PASSWORD '$app_pw';" >/dev/null
fi
pg_pw="$(docker exec "$PG" printenv POSTGRES_PASSWORD)"
app_pw="$(docker exec "$PG" printenv SF_APP_PASSWORD)"

args=("$@")
[[ ${#args[@]} -eq 0 ]] && args=(-q -m "not stack")

docker run --rm --network "$NET" -v "$PWD/backend:/app:ro" -w /app \
  -e TEST_DB_HOST="$PG" -e TEST_DB_PORT=5432 -e TEST_DB_USER=postgres -e TEST_DB_PASSWORD="$pg_pw" \
  -e DB_APP_PASSWORD="$app_pw" \
  "$IMAGE" python -m pytest -p no:cacheprovider "${args[@]}"
