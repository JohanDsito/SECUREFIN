"""TS-S15 (T069): la sesión `pre_auth` con los endpoints reales (complementa a SC20 de T134).

- Correlaciona al usuario pendiente sin autenticarlo.
- No da acceso a ninguna ruta protegida.
- Se revoca con el usuario (desactivación, revoke_all) y caduca a los 5 min (10 en un alta).
- La clave rota al pasar a `full`.
- Con MFA activo no se puede "volver a dar de alta" el TOTP desde `pre_auth` (evitaría el MFA).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from rest_framework.permissions import AllowAny

from apps.iam.models import Status, TOTPDevice, UserSession
from apps.iam.services.session_admin import revoke_all
from apps.iam.sessions.store import SessionStore
from tests.helpers import make_totp_device, totp_code
from tests.security.routes import iter_api_routes

pytestmark = pytest.mark.security

GENERIC_401 = {"code": "auth_failed", "message": "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."}
PRE_AUTH_ROUTES = {
    "/api/v1/auth/login/mfa",
    "/api/v1/auth/login/enroll/setup",
    "/api/v1/auth/login/enroll/confirm",
    "/api/v1/auth/login/mfa-reset-request",
    "/api/v1/auth/logout",
}


@pytest.fixture
def pending(api, make_user):
    """Cliente con MFA activo y sesión pre_auth tras una contraseña válida."""
    user = make_user()
    user.totp_secret = make_totp_device(user)
    assert api.login(user.email).json() == {"status": "mfa_required"}
    return api, user


def _protected_routes():
    for path, view_class in iter_api_routes():
        if any(p is AllowAny for p in getattr(view_class, "permission_classes", [])):
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            if hasattr(view_class, method):
                yield path.removeprefix("/api/v1"), method


def test_pre_auth_row_correlates_user_without_authenticating(pending):
    client, user = pending
    row = UserSession.objects.get(user=user)
    assert row.auth_level == "pre_auth" and row.authenticated_at is None
    store = SessionStore(client.session_cookie)
    assert store["_sf_pending_user_id"] == str(user.id)
    assert "_auth_user_id" not in store
    assert client.get("/auth/session").status_code == 401


def test_pre_auth_gives_no_access_to_protected_routes(pending):
    client, _ = pending
    routes = list(_protected_routes())
    assert any(p.startswith("/users/") for p, _ in routes)
    for path, method in routes:
        if method == "get":
            response = client.get(path)
        else:
            response = client._send(method, path, None if method == "delete" else {})
        assert response.status_code == 401, (method, path, response.status_code)
        assert response.json() == {"error": GENERIC_401}


def test_only_contract_routes_accept_pre_auth():
    anonymous = {p for p, v in iter_api_routes() if any(c is AllowAny for c in v.permission_classes)}
    present = {p for p in PRE_AUTH_ROUTES if p in anonymous}
    assert {"/api/v1/auth/login/mfa", "/api/v1/auth/login/enroll/setup", "/api/v1/auth/login/enroll/confirm"} <= present


def test_deactivation_revokes_pre_auth(pending):
    client, user = pending
    user.status = Status.DEACTIVATED
    user.save(update_fields=["status"])
    assert client.post("/auth/login/mfa", {"totp_code": totp_code(user.totp_secret)}).status_code == 401


def test_revoke_all_revokes_pre_auth(pending):
    client, user = pending
    revoke_all(user)
    response = client.post("/auth/login/mfa", {"totp_code": totp_code(user.totp_secret)})
    assert response.status_code == 401
    assert not UserSession.objects.filter(user=user).exists()


def test_revoke_all_after_mfa_revokes_full(pending):
    client, user = pending
    assert client.post("/auth/login/mfa", {"totp_code": totp_code(user.totp_secret)}).status_code == 200
    assert client.get("/auth/session").status_code == 200
    revoke_all(user)
    assert client.get("/auth/session").status_code == 401


def test_pre_auth_expires_after_5_minutes(api, make_user, clock):
    user = make_user()
    secret = make_totp_device(user)
    api.login(user.email)
    clock.advance(minutes=5, seconds=1)
    assert api.post("/auth/login/mfa", {"totp_code": totp_code(secret)}).status_code == 401


def test_pre_auth_valid_before_5_minutes(api, make_user, clock):
    user = make_user()
    secret = make_totp_device(user)
    api.login(user.email)
    clock.advance(minutes=4, seconds=50)
    assert api.post("/auth/login/mfa", {"totp_code": totp_code(secret)}).status_code == 200


@pytest.mark.parametrize(("minutes", "expected"), [(9, 200), (10, 401)])
def test_enrollment_pre_auth_lasts_10_minutes(api, make_user, clock, minutes, expected):
    user = make_user(role="auditor")
    assert api.login(user.email).json() == {"status": "mfa_enrollment_required"}
    assert UserSession.objects.get(user=user).auth_level == "pre_auth"
    clock.advance(minutes=minutes, seconds=1)
    assert api.post("/auth/login/enroll/setup").status_code == expected


def test_key_rotates_from_pre_auth_to_full(pending):
    client, user = pending
    pre_key = client.session_cookie
    response = client.post("/auth/login/mfa", {"totp_code": totp_code(user.totp_secret)})
    assert response.status_code == 200
    assert client.session_cookie and client.session_cookie != pre_key
    assert not SessionStore().exists(pre_key)
    row = UserSession.objects.get(user=user)
    assert row.auth_level == "full"


def test_full_session_inherits_pre_auth_created_at(api, make_user, clock):
    user = make_user()
    secret = make_totp_device(user)
    t0 = clock.now()
    api.login(user.email)
    clock.advance(minutes=3)
    api.post("/auth/login/mfa", {"totp_code": totp_code(secret)})
    row = UserSession.objects.get(user=user)
    assert row.created_at == t0 and row.expire_date == t0 + timedelta(hours=8)


def test_user_with_active_mfa_cannot_re_enroll_from_pre_auth(pending):
    """Sin esto, quien conozca la contraseña daría de alta su propio TOTP y evitaría el MFA."""
    client, user = pending
    assert client.post("/auth/login/enroll/setup").status_code == 401
    assert client.post("/auth/login/enroll/confirm", {"totp_code": "123456"}).status_code == 401
    assert TOTPDevice.objects.filter(user=user).count() == 1
    assert client.get("/auth/session").status_code == 401


def test_enrollment_pre_auth_cannot_use_mfa_step(api, make_user):
    user = make_user(role="admin")
    api.login(user.email)
    assert api.post("/auth/login/mfa", {"totp_code": "123456"}).status_code == 401


def test_mfa_routes_without_pre_auth_are_denied(api, db):
    assert api.post("/auth/login/mfa", {"totp_code": "123456"}).status_code == 401
    assert api.post("/auth/login/enroll/setup").status_code == 401
    assert api.post("/auth/login/enroll/confirm", {"totp_code": "123456"}).status_code == 401


def test_full_session_cannot_use_pre_auth_routes(login_as):
    client, _ = login_as("client")
    assert client.post("/auth/login/mfa", {"totp_code": "123456"}).status_code == 401
    assert client.get("/auth/session").status_code == 200  # la sesión completa no se toca
