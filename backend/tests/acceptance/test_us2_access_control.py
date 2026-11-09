"""TS-A02 (T061): escenarios de aceptación 1, 2, 6 y 7 de US2.

Los escenarios 3–5 (funciones administrativas y de auditoría) los cubre la matriz generada de T058
en cuanto existan las rutas de US4 y US6.
"""

from __future__ import annotations

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.models import User
from tests.security.routes import iter_api_routes

pytestmark = pytest.mark.acceptance

OWN_RESOURCES = ("profile", "sessions", "security")


def test_us2_1_client_reads_and_updates_own_profile(login_as):
    client, user = login_as("client")
    assert client.get("/users/me/profile").status_code == 200
    response = client.patch("/users/me/profile", {"name": "Cliente A Renombrado"})
    assert response.status_code == 200
    user.refresh_from_db()
    assert user.name == "Cliente A Renombrado"
    for resource in OWN_RESOURCES:
        assert client.get(f"/users/{user.id}/{resource}").status_code == 200


def test_us2_2_client_a_denied_on_client_b_without_revealing_existence(login_as):
    client_a, user_a = login_as("client")
    _, user_b = login_as("client")
    for resource in OWN_RESOURCES:
        response = client_a.get(f"/users/{user_b.id}/{resource}")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"
        assert str(user_b.id) not in response.content.decode()
    events = SecurityEvent.objects.filter(event_type="authz_denied", actor_id=user_a.id, outcome="denied")
    assert events.count() == len(OWN_RESOURCES)
    assert {e.metadata["path"] for e in events} == {
        f"/api/v1/users/{user_b.id}/{resource}" for resource in OWN_RESOURCES
    }


@pytest.mark.parametrize("path", sorted({p for p, _ in iter_api_routes() if p.startswith("/api/v1/users/")}))
def test_us2_6_no_session_denied(api, db, path):
    response = api.get(path.removeprefix("/api/v1"))
    assert response.status_code in (401, 405)  # 405 solo si la ruta no admite GET
    if response.status_code == 401:
        assert response.json()["error"]["code"] == "auth_failed"


def test_us2_6_revoked_session_denied(login_as):
    client, _ = login_as("client")
    client.post("/auth/logout")
    for resource in OWN_RESOURCES:
        assert client.get(f"/users/me/{resource}").status_code == 401


@pytest.mark.parametrize(
    "privileged",
    [{"role": "admin"}, {"status": "deactivated"}, {"mfa_enabled": True}, {"mfa_required": False}],
)
def test_us2_7_privileged_fields_never_applied(login_as, privileged):
    client, user = login_as("client")
    response = client.patch("/users/me/profile", {"name": "Intento", **privileged})
    assert response.status_code == 400
    user.refresh_from_db()
    assert user.role == "client" and user.status == "active" and user.name != "Intento"
    assert client.get("/users/me/security").json()["mfa_enabled"] is False
    assert User.objects.filter(role="admin").count() == 0
