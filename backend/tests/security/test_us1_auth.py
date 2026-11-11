"""Seguridad de US1 (T049): cookie, enumeración, asignación masiva, entradas enormes y MFA obligatorio."""

from unittest import mock

import pytest

from apps.iam.models import User, UserSession
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.security


def test_s04_session_cookie_attributes(api, make_user):
    response = api.login(make_user().email)
    header = response.cookies["__Host-sf_session"].output()
    assert "HttpOnly" in header and "Secure" in header and "SameSite=Strict" in header
    assert "Path=/" in header
    assert "Domain" not in header
    assert "expires" not in header.lower() and "max-age" not in header.lower()


def test_enumeration_identical_bodies(api_factory, make_user):
    user = make_user()
    wrong = api_factory().login(user.email, "contraseña incorrecta larga")
    unknown = api_factory().login("inexistente@lab.securefin.local", "contraseña incorrecta larga")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.content == unknown.content


@pytest.mark.parametrize("extra", [{"role": "admin"}, {"status": "active"}, {"mfa_enabled": True}, {"is_staff": True}])
def test_s20_mass_assignment_rejected(api, db, extra):
    payload = {"email": "masivo@lab.securefin.local", "name": "Masivo", "password": STRONG_PASSWORD, **extra}
    response = api.post("/auth/register", payload)
    assert response.status_code == 400
    assert not User.objects.exists()


def test_s22_huge_password_rejected_without_hashing(api, db):
    with mock.patch("django.contrib.auth.hashers.make_password") as hasher, \
         mock.patch("apps.iam.models.User.set_password") as setter:
        response = api.post("/auth/register", {"email": "largo@lab.securefin.local", "name": "Largo", "password": "x" * 129})
    assert response.status_code == 400
    hasher.assert_not_called()
    setter.assert_not_called()


def test_s22_huge_password_login_rejected_without_hashing(api, make_user):
    user = make_user()
    with mock.patch("apps.iam.models.User.check_password") as checker:
        response = api.login(user.email, "x" * 129)
    assert response.status_code == 400
    checker.assert_not_called()


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_privileged_roles_never_get_full_session_without_mfa(api, make_user, role):
    user = make_user(role=role)
    api.login(user.email)
    assert not UserSession.objects.filter(user=user, auth_level="full").exists()
    assert api.get("/auth/session").status_code == 401
