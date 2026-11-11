"""TS-SC15–SC20 (T134): emisión de la cookie, renovación sin reemitir, session_expired, origen del
límite absoluto, CSRF sin sesiones y usuario pendiente en pre_auth (C2, I1, I3, U3)."""

import secrets
from datetime import timedelta

import pytest
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

from apps.audit.models import SecurityEvent
from apps.iam.api.permissions import IsFullyAuthenticated
from apps.iam.models import UserSession
from apps.iam.services import authentication
from apps.iam.services.session_admin import revoke_all
from apps.iam.sessions import keys as K
from apps.iam.sessions.store import SessionStore
from tests.helpers import build_session, session_cookie_deleted, session_cookie_set, use_session

pytestmark = pytest.mark.session_conformance


# --- SC15: sin Set-Cookie innecesario -------------------------------------------------------------
def test_sc15_cookie_only_on_creation_rotation_and_deletion(api, make_user, clock):
    user = make_user()
    login = api.login(user.email)
    assert session_cookie_set(login)  # creación
    for _ in range(3):
        clock.advance(minutes=2)
        response = api.get("/auth/session")
        assert response.status_code == 200
        assert "__Host-sf_session" not in response.cookies  # nunca se reemite
    logout = api.post("/auth/logout")
    assert session_cookie_deleted(logout)  # borrado


def test_sc15_login_again_rotates_and_emits(api, make_user):
    user = make_user()
    api.login(user.email)
    first = api.session_cookie
    second_login = api.login(user.email)
    assert session_cookie_set(second_login) and api.session_cookie != first


# --- SC16: renovación sin modificar el contenido ---------------------------------------------------
def test_sc16_touch_updates_only_last_activity(make_user, clock):
    user = make_user()
    key = build_session(user)
    before = UserSession.objects.get()
    clock.advance(seconds=61)
    store = SessionStore(key)
    assert store[K.LEVEL] == K.FULL
    assert store.touch() is True
    assert store.modified is False
    after = UserSession.objects.get()
    assert after.last_activity_at > before.last_activity_at
    assert (after.session_data, after.expire_date, after.key_verifier) == (
        before.session_data,
        before.expire_date,
        before.key_verifier,
    )


def test_sc16_no_write_within_granularity(make_user, clock):
    user = make_user()
    key = build_session(user)
    before = UserSession.objects.get().last_activity_at
    clock.advance(seconds=30)
    store = SessionStore(key)
    store[K.LEVEL]
    assert store.touch() is False
    assert UserSession.objects.get().last_activity_at == before


# --- SC17: session_expired solo para sesiones válidas ---------------------------------------------
@pytest.mark.parametrize("advance,reason", [({"minutes": 16}, "idle"), ({"hours": 8, "seconds": 1}, "absolute")])
def test_sc17_expired_valid_session_emits_exactly_one_event(api, make_user, clock, advance, reason):
    user = make_user()
    key = build_session(user)
    use_session(api, key)
    clock.advance(**advance)
    assert api.get("/auth/session").status_code == 401
    events = SecurityEvent.objects.filter(event_type="session_expired")
    assert events.count() == 1
    event = events.get()
    assert event.actor_id == user.id and event.metadata["reason"] == reason


@pytest.mark.parametrize("cookie", [secrets.token_urlsafe(32), "corta", "!" * 50])
def test_sc17_junk_cookies_emit_no_events(api, db, cookie):
    api.client.cookies["__Host-sf_session"] = cookie
    api.get("/auth/session")
    assert not SecurityEvent.objects.filter(event_type="session_expired").exists()


def test_sc17_purged_session_emits_no_event(api, make_user):
    user = make_user()
    key = build_session(user)
    UserSession.objects.all().delete()  # purga
    use_session(api, key)
    api.get("/auth/session")
    assert not SecurityEvent.objects.filter(event_type="session_expired").exists()


# --- SC18: límite absoluto desde el created_at inicial (I3) ----------------------------------------
def _elevate(key, user, rf=RequestFactory()):
    request = rf.post("/api/v1/auth/login/mfa")
    request.session = SessionStore(key)
    request.user = AnonymousUser()
    authentication.start_full_session(request, user, "203.0.113.10")
    request.session.save()
    return request.session.session_key


def test_sc18_full_session_inherits_pre_auth_created_at(api, make_user, clock):
    user = make_user()
    t0 = clock.now()
    pre_key = build_session(user, level=K.PRE_AUTH, created_at=t0)
    clock.advance(minutes=4)
    full_key = _elevate(pre_key, user)
    assert full_key != pre_key
    row = UserSession.objects.get()
    assert row.auth_level == K.FULL
    assert row.created_at == t0
    assert row.expire_date == t0 + timedelta(hours=8)
    use_session(api, full_key)
    # Rotación por cambio de MFA a t0 + 4 h: no mueve created_at ni expire_date
    while clock.now() < t0 + timedelta(hours=4):
        clock.advance(minutes=10)
        assert api.get("/auth/session").status_code == 200
    store = SessionStore(api.session_cookie)
    store[K.LEVEL]
    store.cycle_key()
    store.save()
    use_session(api, store.session_key)
    rotated = UserSession.objects.get()
    assert rotated.created_at == t0 and rotated.expire_date == t0 + timedelta(hours=8)
    while clock.now() < t0 + timedelta(hours=7, minutes=59):
        clock.advance(minutes=10)
        if clock.now() >= t0 + timedelta(hours=8):
            break
        assert api.get("/auth/session").status_code == 200
    clock.current = t0 + timedelta(hours=8, seconds=1)
    assert api.get("/auth/session").status_code == 401


def test_sc18_idle_still_15_minutes_after_elevation(api, make_user, clock):
    user = make_user()
    pre_key = build_session(user, level=K.PRE_AUTH)
    full_key = _elevate(pre_key, user)
    use_session(api, full_key)
    clock.advance(minutes=15, seconds=1)
    assert api.get("/auth/session").status_code == 401


# --- SC19: CSRF sin sesiones (I1) -----------------------------------------------------------------
def test_sc19_csrf_and_failed_login_create_no_sessions(api, make_user):
    user = make_user()
    response = api.fetch_csrf()
    assert response.status_code == 204
    assert "__Host-sf_csrftoken" in response.cookies
    assert not session_cookie_set(response)
    assert UserSession.objects.count() == 0
    failed = api.login(user.email, "contraseña equivocada pero larga")
    assert failed.status_code == 401
    assert not session_cookie_set(failed)
    assert UserSession.objects.count() == 0


def test_sc19_anonymous_routes_still_require_csrf(api, make_user):
    user = make_user()
    api.fetch_csrf()
    without = api.post("/auth/login", {"email": user.email, "password": "x" * 20}, csrf=False)
    assert without.status_code == 403
    with_token = api.post("/auth/login", {"email": user.email, "password": "x" * 20})
    assert with_token.status_code == 401
    assert UserSession.objects.count() == 0


# --- SC20: usuario pendiente en pre_auth (U3) -------------------------------------------------------
def test_sc20_pre_auth_correlates_owner_without_authenticating(api, make_user):
    user = make_user()
    key = build_session(user, level=K.PRE_AUTH)
    row = UserSession.objects.get()
    assert row.user_id == user.id and row.auth_level == K.PRE_AUTH
    use_session(api, key)
    assert api.get("/auth/session").status_code == 401  # request.user anónimo
    request = RequestFactory().get("/")
    request.session = SessionStore(key)
    request.user = AnonymousUser()
    assert IsFullyAuthenticated().has_permission(request, None) is False


def test_sc20_revoke_all_removes_pre_auth_and_full(api_factory, make_user):
    user = make_user()
    pre_key = build_session(user, level=K.PRE_AUTH)
    full_client = api_factory()
    full_client.login(user.email)
    assert UserSession.objects.filter(user=user).count() == 2
    revoke_all(user)
    assert UserSession.objects.filter(user=user).count() == 0
    assert full_client.get("/auth/session").status_code == 401
    assert not SessionStore().exists(pre_key)


@pytest.mark.parametrize("ttl,ok_at,expired_at", [(None, 4, 6), (600, 9, 11)])
def test_sc20_pre_auth_expiry(make_user, clock, ttl, ok_at, expired_at):
    user = make_user()
    key = build_session(user, level=K.PRE_AUTH, ttl=ttl)
    start = clock.now()
    clock.current = start + timedelta(minutes=ok_at)
    assert SessionStore(key).get(K.LEVEL) == K.PRE_AUTH
    clock.current = start + timedelta(minutes=expired_at)
    assert SessionStore(key).get(K.LEVEL) is None


def test_sc20_pending_user_removed_after_elevation(make_user):
    user = make_user()
    pre_key = build_session(user, level=K.PRE_AUTH)
    full_key = _elevate(pre_key, user)
    store = SessionStore(full_key)
    assert store.get(K.PENDING_USER) is None
    assert store[K.DJANGO_USER] == str(user.id)
    assert UserSession.objects.get().user_id == user.id
