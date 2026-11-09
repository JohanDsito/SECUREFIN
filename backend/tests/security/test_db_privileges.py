"""TS-S16 / TS-S26 (T022): la auditoría es append-only frente al rol de ejecución `securefin_app`.

La comprobación de credenciales por servicio vive solo en T120 (marcador `stack`; corrección D1).
"""

import os

import psycopg
import pytest
from django.db import DatabaseError, connection, transaction

from apps.audit.services import record_event

pytestmark = pytest.mark.security


@pytest.fixture
def app_cursor(db):
    password = os.environ.get("DB_APP_PASSWORD")
    if not password:
        pytest.fail("DB_APP_PASSWORD no está definida: esta prueba necesita el rol securefin_app.")
    cfg = connection.settings_dict
    with psycopg.connect(
        host=cfg["HOST"], port=cfg["PORT"], dbname=cfg["NAME"], user="securefin_app",
        password=password, autocommit=True,
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SET search_path = securefin, public")
            yield cursor


def test_app_role_has_only_insert_and_select_on_audit(app_cursor):
    def priv(p):
        app_cursor.execute("SELECT has_table_privilege('securefin_app', 'audit_securityevent', %s)", [p])
        return app_cursor.fetchone()[0]

    assert priv("INSERT") and priv("SELECT")
    assert not priv("UPDATE") and not priv("DELETE") and not priv("TRUNCATE")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_securityevent SET outcome = 'failure' WHERE false",
        "DELETE FROM audit_securityevent WHERE false",
        "TRUNCATE audit_securityevent",
        "ALTER TABLE audit_securityevent ADD COLUMN intruso int",
        "DROP TRIGGER audit_securityevent_no_update_delete ON audit_securityevent",
        "ALTER TABLE audit_securityevent DISABLE TRIGGER ALL",
    ],
)
def test_app_role_cannot_modify_or_disable_audit(app_cursor, statement):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_cursor.execute(statement)


def test_app_role_keeps_dml_on_iam_tables(app_cursor):
    app_cursor.execute("SELECT has_table_privilege('securefin_app', 'iam_user', 'DELETE')")
    assert app_cursor.fetchone()[0] is True


@pytest.mark.parametrize("statement", ["UPDATE audit_securityevent SET outcome = 'failure'",
                                       "DELETE FROM audit_securityevent", "TRUNCATE audit_securityevent"])
def test_triggers_block_even_privileged_application_writes(db, statement):
    record_event("logout", "success")
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(statement)
