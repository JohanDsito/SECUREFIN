"""TS-S02 (T059): autorización a nivel de objeto (BOLA/IDOR; FR-017).

El Cliente A intenta operar sobre los recursos del Cliente B con su identificador real y con
identificadores secuenciales, aleatorios y mal formados. Siempre: 404 con el mismo cuerpo (no revela
si el recurso existe), sin efecto sobre B y con un evento `authz_denied` (motivo `object`).
"""

from __future__ import annotations

import uuid

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.models import User, UserSession

pytestmark = pytest.mark.security

NOT_FOUND = {"error": {"code": "not_found", "message": "Recurso no encontrado."}}
FOREIGN_IDS = ["1", "2", "0", "-1", str(uuid.uuid4()), "abc", "me2", "ME", "null", "%2e%2e"]


@pytest.fixture
def clients(login_as):
    client_a, user_a = login_as("client")
    client_b, user_b = login_as("client")
    session_b = UserSession.objects.get(user=user_b)
    return client_a, user_a, client_b, user_b, session_b


def _denied(user):
    return SecurityEvent.objects.filter(event_type="authz_denied", actor_id=user.id, metadata__reason="object")


def _assert_hidden(response):
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


def test_client_a_cannot_read_b_resources(clients):
    client_a, user_a, _, user_b, _ = clients
    for suffix in ("profile", "sessions", "security"):
        before = _denied(user_a).count()
        _assert_hidden(client_a.get(f"/users/{user_b.id}/{suffix}"))
        assert _denied(user_a).count() == before + 1


def test_client_a_cannot_modify_b_profile(clients):
    client_a, user_a, _, user_b, _ = clients
    _assert_hidden(client_a.patch(f"/users/{user_b.id}/profile", {"name": "Nombre Cambiado"}))
    user_b.refresh_from_db()
    assert user_b.name != "Nombre Cambiado"
    assert _denied(user_a).exists()


def test_client_a_cannot_revoke_b_session_through_b_path(clients):
    client_a, user_a, client_b, user_b, session_b = clients
    _assert_hidden(client_a.delete(f"/users/{user_b.id}/sessions/{session_b.public_id}"))
    assert UserSession.objects.filter(public_id=session_b.public_id).exists()
    assert client_b.get("/auth/session").status_code == 200
    assert _denied(user_a).exists()


def test_client_a_cannot_revoke_b_session_through_own_path(clients):
    """`me` + public_id ajeno: la sesión de B no es de A → 404, igual que una inexistente."""
    client_a, user_a, client_b, _, session_b = clients
    foreign = client_a.delete(f"/users/me/sessions/{session_b.public_id}")
    missing = client_a.delete(f"/users/me/sessions/{uuid.uuid4()}")
    _assert_hidden(foreign)
    assert foreign.content == missing.content
    assert UserSession.objects.filter(public_id=session_b.public_id).exists()
    assert client_b.get("/auth/session").status_code == 200
    assert _denied(user_a).count() >= 2


@pytest.mark.parametrize("public_id", ["1", "abc", "00000000-0000-0000-0000-000000000000"])
def test_malformed_session_ids_are_hidden(clients, public_id):
    client_a, user_a, *_ = clients
    _assert_hidden(client_a.delete(f"/users/me/sessions/{public_id}"))


@pytest.mark.parametrize("foreign_id", FOREIGN_IDS)
@pytest.mark.parametrize("suffix", ["profile", "sessions", "security"])
def test_sequential_random_and_malformed_ids(clients, suffix, foreign_id):
    client_a, user_a, *_ = clients
    before = _denied(user_a).count()
    _assert_hidden(client_a.get(f"/users/{foreign_id}/{suffix}"))
    assert _denied(user_a).count() == before + 1


def test_existing_and_nonexistent_users_are_indistinguishable(clients):
    client_a, _, _, user_b, _ = clients
    existing = client_a.get(f"/users/{user_b.id}/profile")
    nonexistent = client_a.get(f"/users/{uuid.uuid4()}/profile")
    assert existing.status_code == nonexistent.status_code == 404
    assert existing.content == nonexistent.content


def test_denials_never_change_other_users(clients):
    client_a, _, _, user_b, _ = clients
    snapshot = User.objects.values().get(pk=user_b.pk)
    client_a.patch(f"/users/{user_b.id}/profile", {"name": "X"})
    client_a.delete(f"/users/{user_b.id}/sessions/{uuid.uuid4()}")
    assert User.objects.values().get(pk=user_b.pk) == snapshot
