"""TS-A01 (T050): escenarios de aceptación de US1. El escenario 4 (gestores de contraseñas, pegar y
autocompletar) es comportamiento del navegador y lo cubre la E2E T133."""

import pytest

from apps.iam.models import User, UserSession
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.acceptance


def test_us1_1_register_with_valid_data_creates_client_with_argon2id(api, db):
    r = api.post("/auth/register", {"email": "c1@lab.securefin.local", "name": "Cliente Uno", "password": STRONG_PASSWORD})
    assert r.status_code == 201
    user = User.objects.get(email="c1@lab.securefin.local")
    assert user.role == "client" and user.password.startswith("argon2$argon2id$")


def test_us1_2_manipulated_role_is_rejected(api, db):
    r = api.post("/auth/register", {"email": "c2@lab.securefin.local", "name": "C2", "password": STRONG_PASSWORD, "role": "admin"})
    assert r.status_code == 400
    assert not User.objects.filter(role="admin").exists()


@pytest.mark.parametrize("password", ["corta123456789", "z" * 129, "passwordpassword", "securefin-gateway-2026"])
def test_us1_3_weak_password_rejected_with_rule(api, db, password):
    r = api.post("/auth/register", {"email": "c3@lab.securefin.local", "name": "C3", "password": password})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "validation_error"
    assert r.json()["error"]["message"]


def test_us1_5_login_grants_authenticated_session(api, make_user):
    user = make_user()
    r = api.login(user.email)
    assert r.json()["status"] == "authenticated"
    assert api.get("/auth/session").status_code == 200


def test_us1_6_same_generic_message_for_unknown_or_wrong(api_factory, make_user):
    user = make_user()
    a = api_factory().login("noexiste@lab.securefin.local", "contraseña incorrecta larga")
    b = api_factory().login(user.email, "contraseña incorrecta larga")
    assert a.json() == b.json() and a.status_code == b.status_code == 401


def test_us1_7_logout_revokes_session(api, make_user):
    api.login(make_user().email)
    api.post("/auth/logout")
    assert api.get("/auth/session").status_code == 401


@pytest.mark.parametrize("advance", [{"minutes": 16}, {"hours": 8, "seconds": 1}])
def test_us1_8_idle_or_absolute_expiry_requires_reauthentication(api, make_user, clock, advance):
    api.login(make_user().email)
    if "hours" in advance:  # mantener actividad para que solo actúe el límite absoluto
        for _ in range(47):
            clock.advance(minutes=10)
            api.get("/auth/session")
        clock.advance(minutes=10, seconds=1)
    else:
        clock.advance(**advance)
    assert api.get("/auth/session").status_code == 401
    assert not UserSession.objects.exists()
