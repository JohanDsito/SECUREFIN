from django.db import migrations


FORWARD = r"""
CREATE OR REPLACE FUNCTION finance_ledgerentry_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'finance_ledgerentry es append-only: % no permitido', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS finance_ledgerentry_no_update_delete ON finance_ledgerentry;
CREATE TRIGGER finance_ledgerentry_no_update_delete
  BEFORE UPDATE OR DELETE ON finance_ledgerentry
  FOR EACH ROW EXECUTE FUNCTION finance_ledgerentry_immutable();

DROP TRIGGER IF EXISTS finance_ledgerentry_no_truncate ON finance_ledgerentry;
CREATE TRIGGER finance_ledgerentry_no_truncate
  BEFORE TRUNCATE ON finance_ledgerentry
  FOR EACH STATEMENT EXECUTE FUNCTION finance_ledgerentry_immutable();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securefin_app') THEN
    GRANT SELECT, INSERT ON finance_ledgerentry TO securefin_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON finance_ledgerentry FROM securefin_app;
  END IF;
END $$;
"""

BACKWARD = r"""
DROP TRIGGER IF EXISTS finance_ledgerentry_no_update_delete ON finance_ledgerentry;
DROP TRIGGER IF EXISTS finance_ledgerentry_no_truncate ON finance_ledgerentry;
DROP FUNCTION IF EXISTS finance_ledgerentry_immutable();
"""


class Migration(migrations.Migration):
    dependencies = [("finance", "0001_initial")]

    operations = [migrations.RunSQL(FORWARD, BACKWARD)]
