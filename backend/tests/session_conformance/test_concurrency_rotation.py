"""TS-SC11–SC14 (T021): concurrencia, rotación de clave, fallo cerrado e inspección de PostgreSQL."""

import asyncio
import base64
import os
import secrets
from pathlib import Path
from unittest import mock

import pytest
from django.contrib.sessions.backends.base import UpdateError
from django.core.exceptions import FieldError
from django.core.management import CommandError, call_command
from django.db import connection

from apps.core import keys
from apps.iam.models import UserSession
from apps.iam.sessions import keys as K
from apps.iam.sessions.store import SessionStore
from tests.helpers import build_session, use_session

pytestmark = pytest.mark.session_conformance


def test_sc11_revoked_session_is_never_resurrected(make_user):
    user = make_user()
    key = build_session(user)
    store = SessionStore(key)
    store.load()
    store["dato"] = "modificado"  # petición en curso que va a guardar
    UserSession.objects.all().delete()  # revocación concurrente
    with pytest.raises(UpdateError):
        store.save()
    assert UserSession.objects.count() == 0


def test_sc11_creation_collision_retries(make_user):
    user = make_user()
    existing = build_session(user)
    fresh = secrets.token_urlsafe(32)
    store = SessionStore()
    store[K.LEVEL] = K.FULL
    store[K.DJANGO_USER] = str(user.id)
    with mock.patch.object(SessionStore, "_get_new_session_key", side_effect=[existing, fresh]):
        store.create()
    assert store.session_key == fresh
    assert UserSession.objects.count() == 2


def test_sc11_parallel_saves_same_session_do_not_corrupt(make_user):
    user = make_user()
    key = build_session(user)
    a, b = SessionStore(key), SessionStore(key)
    a.load(), b.load()
    a["x"] = 1
    b["y"] = 2
    a.save()
    b.save()  # último en escribir gana; la sesión sigue siendo válida
    reloaded = SessionStore(key)
    assert reloaded[K.LEVEL] == K.FULL and reloaded["y"] == 2


@pytest.fixture
def session_key_v2(monkeypatch):
    directory = Path(os.environ["SECUREFIN_SECRETS_DIR"])
    v2 = directory / "session_hmac_key_v2"
    v2.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    yield monkeypatch
    v2.unlink(missing_ok=True)
    keys.reset_cache()


def test_sc12_rotation_and_retirement(api, make_user, session_key_v2):
    user = make_user()
    api.login(user.email)
    old_cookie = api.session_cookie
    assert UserSession.objects.get().key_version == "v1"

    session_key_v2.setenv("SESSION_HMAC_KEY_VERSIONS", "v2,v1")
    keys.reset_cache()
    assert api.get("/auth/session").status_code == 200  # v1 sigue aceptada
    other = api.__class__()
    other.login(user.email)
    assert UserSession.objects.filter(key_version="v2").count() == 1

    with pytest.raises(CommandError):
        call_command("iam_rotate_session_key", retire="v2")  # no se puede retirar la activa
    session_key_v2.setenv("SESSION_HMAC_KEY_VERSIONS", "v2")
    keys.reset_cache()
    call_command("iam_rotate_session_key", retire="v1")
    use_session(api, old_cookie)
    assert api.get("/auth/session").status_code == 401
    assert other.get("/auth/session").status_code == 200


def test_sc12_emergency_rotation_logs_everyone_out(api, make_user, session_key_v2):
    user = make_user()
    api.login(user.email)
    session_key_v2.setenv("SESSION_HMAC_KEY_VERSIONS", "v2")
    keys.reset_cache()
    call_command("iam_rotate_session_key", retire="v1")
    assert api.get("/auth/session").status_code == 401
    assert UserSession.objects.count() == 0


def test_sc13_async_api_not_supported_and_fail_closed(db):
    store = SessionStore()
    for coro in (store.aload(), store.asave(), store.acreate(), store.aexists("x"),
                 store.adelete("x"), store.acycle_key(), SessionStore.aclear_expired()):
        with pytest.raises(NotImplementedError):
            asyncio.run(coro)
    with pytest.raises(FieldError):
        list(UserSession.objects.filter(session_key="x"))


def test_sc14_database_dump_contains_no_cookie(api_factory, make_user):
    cookies = []
    for _ in range(3):
        client = api_factory()
        client.login(make_user().email)
        client.get("/auth/session")
        cookies.append(client.session_cookie)
    with connection.cursor() as cursor:
        dump = []
        for table in connection.introspection.table_names(cursor):
            cursor.execute(f'SELECT row_to_json(t)::text FROM "{table}" t')
            dump.extend(r[0] for r in cursor.fetchall())
    text = "\n".join(dump)
    assert all(c and c not in text for c in cookies)
