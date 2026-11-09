"""TS-C01, parte US2 (T060): contrato de /users/{user_id}/… (contrato §3)."""

from __future__ import annotations

import pytest

from apps.iam.models import User, UserSession

pytestmark = pytest.mark.contract

SENSITIVE = ("password", "hash", "secret", "token", "key_verifier", "session_data", "verifier")
PROFILE_FIELDS = {"id", "email", "name", "role", "created_at"}
SESSION_FIELDS = {"public_id", "created_at", "last_activity_at", "ip_address", "user_agent", "current"}
SECURITY_FIELDS = {"mfa_enabled", "mfa_required", "recovery_codes_remaining"}


def _no_sensitive(payload):
    text = str(payload).lower()
    assert not any(word in text for word in SENSITIVE), payload


def _api_headers(response):
    assert response["Cache-Control"] == "no-store"
    assert "Access-Control-Allow-Origin" not in response


@pytest.mark.parametrize("alias", ["me", "own_id"])
def test_get_profile(login_as, alias):
    client, user = login_as("client")
    user_id = "me" if alias == "me" else str(user.id)
    response = client.get(f"/users/{user_id}/profile")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == PROFILE_FIELDS
    assert body["id"] == str(user.id) and body["email"] == user.email and body["role"] == "client"
    _no_sensitive(body)
    _api_headers(response)


def test_patch_profile_name(login_as):
    client, user = login_as("client")
    response = client.patch("/users/me/profile", {"name": "Nombre Nuevo"})
    assert response.status_code == 200
    assert set(response.json()) == PROFILE_FIELDS
    assert response.json()["name"] == "Nombre Nuevo"
    user.refresh_from_db()
    assert user.name == "Nombre Nuevo"
    assert "__Host-sf_session" not in response.cookies  # no se reemite la cookie


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "Válido", "role": "admin"},
        {"name": "Válido", "status": "deactivated"},
        {"name": "Válido", "email": "otro@lab.securefin.local"},
        {"name": "Válido", "mfa_enabled": False},
        {"name": "Válido", "mfa_required": False},
        {"name": "Válido", "id": "00000000-0000-0000-0000-000000000000"},
        {"name": "Válido", "created_at": "2020-01-01T00:00:00Z"},
        {"role": "admin"},
        {},
        {"name": ""},
        {"name": "x" * 101},
        {"name": "Con\u0000control"},
        {"name": None},
        ["name"],
    ],
)
def test_patch_profile_rejects_other_fields_and_invalid_names(login_as, payload):
    client, user = login_as("client")
    snapshot = User.objects.values().get(pk=user.pk)
    response = client.patch("/users/me/profile", payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"
    assert User.objects.values().get(pk=user.pk) == snapshot


def test_list_sessions(login_as):
    client, user = login_as("client")
    other, _ = login_as(user=user)  # segunda sesión del mismo usuario
    response = client.get("/users/me/sessions")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list) and len(body) == 2
    for item in body:
        assert set(item) == SESSION_FIELDS
    _no_sensitive(body)
    assert [item["current"] for item in body].count(True) == 1
    current = next(item for item in body if item["current"])
    assert current["public_id"] == client.get("/auth/session").json()["session"]["public_id"]
    assert {item["public_id"] for item in body} == {
        str(pid) for pid in UserSession.objects.filter(user=user).values_list("public_id", flat=True)
    }
    _api_headers(response)


def test_list_sessions_only_own(login_as):
    client, user = login_as("client")
    login_as("client")  # sesión de otro usuario
    body = client.get("/users/me/sessions").json()
    assert len(body) == 1


def test_delete_other_own_session(login_as):
    """V18: revocación inmediata de otra sesión propia."""
    client, user = login_as("client")
    other, _ = login_as(user=user)
    other_public_id = other.get("/auth/session").json()["session"]["public_id"]
    response = client.delete(f"/users/me/sessions/{other_public_id}")
    assert response.status_code == 204
    assert not UserSession.objects.filter(public_id=other_public_id).exists()
    assert other.get("/auth/session").status_code == 401
    assert client.get("/auth/session").status_code == 200
    assert "__Host-sf_session" not in response.cookies  # la sesión actual no cambia


def test_delete_current_session_clears_cookie(login_as):
    client, user = login_as("client")
    public_id = client.get("/auth/session").json()["session"]["public_id"]
    response = client.delete(f"/users/{user.id}/sessions/{public_id}")
    assert response.status_code == 204
    assert response.cookies["__Host-sf_session"].value == ""  # cookie eliminada
    assert not UserSession.objects.filter(public_id=public_id).exists()
    assert client.get("/auth/session").status_code == 401


def test_get_security(login_as):
    client, _ = login_as("client")
    response = client.get("/users/me/security")
    assert response.status_code == 200
    assert response.json() == {"mfa_enabled": False, "mfa_required": False, "recovery_codes_remaining": 0}
    _api_headers(response)


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_get_security_privileged_roles(login_as, role):
    client, _ = login_as(role)
    body = client.get("/users/me/security").json()
    assert set(body) == SECURITY_FIELDS and body["mfa_required"] is True


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [("patch", "/users/me/profile", {"name": "Sin CSRF"}), ("delete", "/users/me/sessions/{pid}", None)],
)
def test_unsafe_methods_require_csrf(login_as, method, path, payload):
    client, user = login_as("client")
    public_id = client.get("/auth/session").json()["session"]["public_id"]
    path = path.format(pid=public_id)
    if method == "patch":
        response = client.patch(path, payload, csrf=False)
    else:
        response = client.delete(path, csrf=False)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    user.refresh_from_db()
    assert user.name != "Sin CSRF"
    assert UserSession.objects.filter(public_id=public_id).exists()


@pytest.mark.parametrize("method", ["post", "put"])
def test_profile_other_methods_not_allowed(login_as, method):
    client, _ = login_as("client")
    response = getattr(client, "_send")(method, "/users/me/profile", {"name": "X"})
    assert response.status_code == 405
