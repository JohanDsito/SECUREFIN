"""Protección append-only de la auditoría frente a la aplicación (T038; R14; NFR-006).

- Triggers BEFORE UPDATE OR DELETE (por fila) y BEFORE TRUNCATE (por sentencia) que lanzan excepción.
- Revoca UPDATE, DELETE y TRUNCATE al rol de ejecución `securefin_app` (si existe).

Limitación documentada: el superusuario `postgres` y el propietario de la tabla pueden desactivar
los triggers; no hay inmutabilidad absoluta (T-36).
"""

from django.db import migrations

FORWARD = r"""
CREATE OR REPLACE FUNCTION audit_securityevent_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_securityevent es append-only: % no permitido', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_securityevent_no_update_delete ON audit_securityevent;
CREATE TRIGGER audit_securityevent_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_securityevent
  FOR EACH ROW EXECUTE FUNCTION audit_securityevent_immutable();

DROP TRIGGER IF EXISTS audit_securityevent_no_truncate ON audit_securityevent;
CREATE TRIGGER audit_securityevent_no_truncate
  BEFORE TRUNCATE ON audit_securityevent
  FOR EACH STATEMENT EXECUTE FUNCTION audit_securityevent_immutable();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securefin_app') THEN
    GRANT SELECT, INSERT ON audit_securityevent TO securefin_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_securityevent FROM securefin_app;
  END IF;
END $$;
"""

BACKWARD = r"""
DROP TRIGGER IF EXISTS audit_securityevent_no_update_delete ON audit_securityevent;
DROP TRIGGER IF EXISTS audit_securityevent_no_truncate ON audit_securityevent;
DROP FUNCTION IF EXISTS audit_securityevent_immutable();
"""


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [migrations.RunSQL(FORWARD, BACKWARD)]
