"""TS-SC01–SC04 (T019): esquema y almacenamiento sin la clave de sesión en claro."""

import re
import secrets
from unittest import mock

import pytest
from django.db import IntegrityError, connection, transaction

from apps.iam.models import UserSession
from apps.iam.sessions.store import SessionStore
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.session_conformance


def test_sc01_no_plaintext_column_and_no_django_session_table(db):
    with connection.cursor() as cursor:
        columns = [c.name for c in connection.introspection.get_table_description(cursor, "iam_usersession")]
        tables = connection.introspection.table_names(cursor)
    assert "session_key" not in columns
    assert "key_verifier" in columns
    assert "django_session" not in tables


def test_sc02_keys_are_256_bit_urlsafe_and_unique(db):
    store = SessionStore()
    with mock.patch.object(SessionStore, "exists", return_value=False):
        sample = {store._get_new_session_key() for _ in range(10_000)}
    assert len(sample) == 10_000
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{43}", k) for k in list(sample)[:100])


def test_sc03_verifier_format_and_version_check(api, make_user):
    user = make_user()
    assert api.login(user.email).status_code == 200
    row = UserSession.objects.get(user=user)
    assert re.fullmatch(r"v1\$[0-9a-f]{64}", row.key_verifier)
    assert len(row.key_verifier) <= 72
    with pytest.raises(IntegrityError), transaction.atomic():
        UserSession.objects.filter(pk=row.pk).update(key_version="v9")


def test_sc04_cookie_value_never_reaches_sql(api, make_user):
    user = make_user()
    statements: list[str] = []

    def collector(execute, sql, params, many, context):
        statements.append(f"{sql} {params!r}")
        return execute(sql, params, many, context)

    with connection.execute_wrapper(collector):
        api.fetch_csrf()
        api.login(user.email, STRONG_PASSWORD)
        cookie = api.session_cookie
        api.get("/auth/session")
        api.get("/auth/session")
        api.post("/auth/logout")
    assert cookie and len(statements) > 5
    assert not any(cookie in s for s in statements)


def test_sc04_random_cookie_probe_never_reaches_sql(api, db):
    probe = secrets.token_urlsafe(32)
    statements: list[str] = []

    def collector(execute, sql, params, many, context):
        statements.append(f"{sql} {params!r}")
        return execute(sql, params, many, context)

    api.client.cookies["__Host-sf_session"] = probe
    with connection.execute_wrapper(collector):
        api.get("/auth/session")
    assert statements, "debe haber consultado por verificador"
    assert not any(probe in s for s in statements)
