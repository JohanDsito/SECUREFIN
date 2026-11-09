#!/bin/sh
# Inicialización de PostgreSQL (T009; R14). Se ejecuta una sola vez como superusuario `postgres`.
# Lee las contraseñas de los secretos montados; nunca las escribe en logs.
set -eu

OWNER_PASSWORD="$(cat /run/secrets/db_owner_password)"
APP_PASSWORD="$(cat /run/secrets/db_app_password)"
DB_NAME="${POSTGRES_DB:-securefin}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" \
     -v owner_password="$OWNER_PASSWORD" -v app_password="$APP_PASSWORD" <<'SQL'
CREATE ROLE securefin_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE securefin_app   LOGIN PASSWORD :'app_password';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO securefin_owner, securefin_app;

CREATE SCHEMA securefin AUTHORIZATION securefin_owner;
GRANT USAGE ON SCHEMA securefin TO securefin_app;      -- sin CREATE

ALTER DEFAULT PRIVILEGES FOR ROLE securefin_owner IN SCHEMA securefin
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO securefin_app;
ALTER DEFAULT PRIVILEGES FOR ROLE securefin_owner IN SCHEMA securefin
  GRANT USAGE, SELECT ON SEQUENCES TO securefin_app;

ALTER ROLE securefin_owner SET search_path = securefin;
ALTER ROLE securefin_app   SET search_path = securefin;
SQL
