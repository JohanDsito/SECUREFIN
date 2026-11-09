"""TS-C01, parte US1 (T047): contrato de /auth/register, /auth/login, /auth/logout y /auth/session."""

import pytest

from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.contract

GENERIC_401 = {"code": "auth_failed", "message": "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."}
SENSITIVE = ("password", "hash", "secret", "token", "key_verifier", "session_data")


def _no_sensitive(payload):
    text = str(payload).lower()
    assert not any(word in text for word in SENSITIVE), payload


def test_register_contract(api, db):
    response = api.post("/auth/register", {"email": "nuevo@lab.securefin.local", "name": "Nuevo", "password": STRONG_PASSWORD})
    assert response.status_code == 201
    assert response.json() == {"status": "registered"}
    assert response["Cache-Control"] == "no-store"


def test_login_authenticated_contract(api, make_user):
    user = make_user()
    response = api.login(user.email)
    body = response.json()
    assert response.status_code == 200 and body["status"] == "authenticated"
    assert set(body["user"]) == {"id", "email", "name", "role", "mfa_enabled", "mfa_required"}
    _no_sensitive(body)
    assert response["Cache-Control"] == "no-store"


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_login_privileged_without_mfa_contract(api, make_user, role):
    user = make_user(role=role)
    response = api.login(user.email)
    assert response.status_code == 200
    assert response.json() == {"status": "mfa_enrollment_required"}


def test_login_failure_contract(api, make_user):
    response = api.login(make_user().email, "contraseña incorrecta larga")
    assert response.status_code == 401
    assert response.json() == {"error": GENERIC_401}


def test_session_contract(api, make_user):
    api.login(make_user().email)
    response = api.get("/auth/session")
    body = response.json()
    assert response.status_code == 200
    assert set(body) == {"user", "session"}
    assert set(body["session"]) == {"public_id", "authenticated_at", "idle_expires_at", "absolute_expires_at"}
    _no_sensitive(body)


def test_session_requires_authentication(api, db):
    response = api.get("/auth/session")
    assert response.status_code == 401
    assert response.json() == {"error": GENERIC_401}


def test_logout_contract(api, make_user):
    api.login(make_user().email)
    response = api.post("/auth/logout")
    assert response.status_code == 204
    assert response.content == b""
