"""TS-I01–I05 (T048): registro, login, logout, /auth/session y rotación de la clave en el login."""

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.models import User, UserSession
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.integration


def test_i01_register_creates_client_with_argon2id(api, db):
    response = api.post("/auth/register", {"email": "Maria@Lab.SecureFin.local", "name": "María", "password": STRONG_PASSWORD})
    assert response.status_code == 201
    user = User.objects.get()
    assert user.email == "maria@lab.securefin.local"
    assert user.role == "client" and user.status == "active"
    assert user.password.startswith("argon2$argon2id$v=19$m=65536,t=3,p=1$")
    assert SecurityEvent.objects.filter(event_type="account_registered", actor_id=user.id).exists()


def test_i01_duplicate_registration_is_neutral(api, make_user):
    user = make_user()
    response = api.post("/auth/register", {"email": user.email.upper(), "name": "Otro", "password": STRONG_PASSWORD})
    assert response.status_code == 400
    assert User.objects.count() == 1
    assert "No fue posible completar el registro" in str(response.json())


def test_i02_login_success_and_events(api, make_user):
    user = make_user()
    assert api.login(user.email).status_code == 200
    assert UserSession.objects.filter(user=user, auth_level="full").count() == 1
    user.refresh_from_db()
    assert user.last_login_at is not None
    assert SecurityEvent.objects.filter(event_type="login_succeeded", actor_id=user.id).exists()


def test_i02_login_failure_event_without_email_for_unknown(api, db):
    api.login("nadie@lab.securefin.local", "contraseña incorrecta larga")
    event = SecurityEvent.objects.get(event_type="login_failed")
    assert event.actor_id is None
    assert "nadie@" not in str(event.metadata)


@pytest.mark.parametrize("status", ["pending_activation", "deactivated"])
def test_i02_inactive_accounts_cannot_login(api, make_user, status):
    user = make_user(status=status)
    assert api.login(user.email).status_code == 401


def test_i03_logout_revokes(api, make_user):
    user = make_user()
    api.login(user.email)
    assert api.post("/auth/logout").status_code == 204
    assert UserSession.objects.count() == 0
    assert api.get("/auth/session").status_code == 401
    assert SecurityEvent.objects.filter(event_type="logout", actor_id=user.id).exists()


def test_i04_session_endpoint(api, make_user):
    user = make_user()
    api.login(user.email)
    body = api.get("/auth/session").json()
    assert body["user"]["id"] == str(user.id)
    assert body["session"]["public_id"] == str(UserSession.objects.get().public_id)


def test_i05_login_rotates_session_key(api, make_user):
    user = make_user()
    api.login(user.email)
    first = api.session_cookie
    api.login(user.email)
    assert api.session_cookie != first
    assert UserSession.objects.filter(user=user).count() == 1
