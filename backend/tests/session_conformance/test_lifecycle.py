"""TS-SC05–SC10 (T020): sesión inválida, fijación, actualización, inactividad, límite absoluto y revocación."""

import secrets
from datetime import timedelta

import pytest

from apps.iam.models import UserSession
from apps.iam.services.session_admin import revoke_all
from apps.iam.sessions import keys as K
from apps.iam.sessions.store import SessionStore
from tests.helpers import build_session, session_cookie_set, use_session

pytestmark = pytest.mark.session_conformance


@pytest.mark.parametrize("cookie", [secrets.token_urlsafe(32), "abc", "x" * 300, "../../etc"])
def test_sc05_invalid_cookie_is_never_adopted(api, db, cookie):
    api.client.cookies["__Host-sf_session"] = cookie
    response = api.get("/auth/session")
    assert response.status_code == 401
    assert UserSession.objects.count() == 0
    assert not session_cookie_set(response)  # nunca se emite ni se adopta un identificador


def test_sc06_presented_identifier_is_never_adopted_on_login(api, make_user):
    user = make_user()
    attacker_value = secrets.token_urlsafe(32)
    api.client.cookies["__Host-sf_session"] = attacker_value
    assert api.login(user.email).status_code == 200
    assert api.session_cookie and api.session_cookie != attacker_value
    assert not SessionStore().exists(attacker_value)


def test_sc06_key_rotates_when_logging_in_again(api, make_user):
    user = make_user()
    api.login(user.email)
    first = api.session_cookie
    api.login(user.email)
    assert api.session_cookie != first
    assert not SessionStore().exists(first)


def test_sc07_data_persists_and_absolute_expiry_is_not_extended(api, make_user, clock):
    user = make_user()
    api.login(user.email)
    row = UserSession.objects.get(user=user)
    original_expiry = row.expire_date
    clock.advance(minutes=5)
    assert api.get("/auth/session").status_code == 200
    row.refresh_from_db()
    assert row.expire_date == original_expiry
    store = SessionStore(api.session_cookie)
    assert store[K.LEVEL] == K.FULL and store[K.DJANGO_USER] == str(user.id)


def test_sc08_idle_timeout_15_minutes(api, make_user, clock):
    user = make_user()
    api.login(user.email)
    clock.advance(minutes=15, seconds=1)
    assert api.get("/auth/session").status_code == 401


def test_sc08_activity_every_10_minutes_keeps_session(api, make_user, clock):
    user = make_user()
    api.login(user.email)
    for _ in range(6):
        clock.advance(minutes=10)
        assert api.get("/auth/session").status_code == 200


def test_sc09_absolute_lifetime_8h_from_initial_created_at(api, make_user, clock):
    user = make_user()
    api.login(user.email)
    created = UserSession.objects.get(user=user).created_at
    for _ in range(47):  # 47 × 10 min = 7 h 50 min
        clock.advance(minutes=10)
        assert api.get("/auth/session").status_code == 200
    clock.current = created + timedelta(hours=8, seconds=1)
    assert api.get("/auth/session").status_code == 401


def test_sc09_cycle_key_inherits_created_at(make_user, clock):
    user = make_user()
    key = build_session(user)
    original = UserSession.objects.get().created_at
    clock.advance(minutes=10)  # dentro de la ventana de inactividad
    store = SessionStore(key)
    assert store[K.LEVEL] == K.FULL
    store.cycle_key()
    rows = list(UserSession.objects.all())
    assert len(rows) == 1 and rows[0].created_at == original


def test_sc10_revoke_all_logout_and_single_revocation(api_factory, make_user):
    user = make_user()
    a, b = api_factory(), api_factory()
    a.login(user.email)
    b.login(user.email)
    assert UserSession.objects.filter(user=user).count() == 2
    revoke_all(user)
    assert a.get("/auth/session").status_code == 401
    assert b.get("/auth/session").status_code == 401
    assert UserSession.objects.filter(user=user).count() == 0


def test_sc10_logout_deletes_row(api, make_user):
    user = make_user()
    api.login(user.email)
    cookie = api.session_cookie
    assert api.post("/auth/logout").status_code == 204
    assert not SessionStore().exists(cookie)
    use_session(api, cookie)
    assert api.get("/auth/session").status_code == 401
