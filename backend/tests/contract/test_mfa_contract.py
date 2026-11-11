"""TS-C01, parte US3 (T070): contrato de /auth/login/mfa, /auth/login/enroll/* y /users/{id}/mfa/*."""

from __future__ import annotations

import base64

import pytest

from apps.iam.crypto.codes import CROCKFORD_ALPHABET
from apps.iam.models import TOTPDevice, UserSession
from apps.iam.services import recovery_codes
from tests.helpers import make_totp_device, session_cookie_set, totp_code

pytestmark = pytest.mark.contract

GENERIC_401 = {"code": "auth_failed", "message": "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."}
USER_SUMMARY = {"id", "email", "name", "role", "mfa_enabled", "mfa_required"}
SETUP_FIELDS = {"otpauth_uri", "qr_svg_data_uri", "secret_base32"}


def _assert_codes(codes):
    assert isinstance(codes, list) and len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        assert len(code) == 28 and set(code) <= set(CROCKFORD_ALPHABET)


def _assert_setup(response):
    assert response.status_code == 200
    body = response.json()
    assert set(body) == SETUP_FIELDS
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert "issuer=SecureFin" in body["otpauth_uri"] and f"secret={body['secret_base32']}" in body["otpauth_uri"]
    assert len(body["secret_base32"]) == 32  # 160 bits
    prefix = "data:image/svg+xml;base64,"
    assert body["qr_svg_data_uri"].startswith(prefix)
    assert base64.b64decode(body["qr_svg_data_uri"][len(prefix):]).lstrip().startswith(b"<")
    assert response["Cache-Control"] == "no-store"
    return body


@pytest.fixture
def pending(api, make_user):
    user = make_user()
    user.totp_secret = make_totp_device(user)
    api.login(user.email)
    return api, user


# --- /auth/login/mfa ------------------------------------------------------------------------------
def test_login_mfa_with_totp(pending):
    client, user = pending
    response = client.post("/auth/login/mfa", {"totp_code": totp_code(user.totp_secret)})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "user"} and body["status"] == "authenticated"
    assert set(body["user"]) == USER_SUMMARY and body["user"]["mfa_enabled"] is True
    assert session_cookie_set(response)
    assert response["Cache-Control"] == "no-store"


def test_login_mfa_with_recovery_code(pending):
    client, user = pending
    codes = recovery_codes.generate_batch(user)
    response = client.post("/auth/login/mfa", {"recovery_code": codes[0]})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "user", "recovery_codes_remaining"}
    assert body["recovery_codes_remaining"] == 9


@pytest.mark.parametrize("payload", [{"totp_code": "000000"}, {"recovery_code": "0" * 28}])
def test_login_mfa_failure_is_generic(pending, payload):
    client, _ = pending
    response = client.post("/auth/login/mfa", payload)
    assert response.status_code == 401
    assert response.json() == {"error": GENERIC_401}
    assert not session_cookie_set(response)


@pytest.mark.parametrize(
    "payload",
    [{}, {"totp_code": "123456", "recovery_code": "0" * 28}, {"totp_code": "123456", "role": "admin"}],
)
def test_login_mfa_validation(pending, payload):
    client, _ = pending
    assert client.post("/auth/login/mfa", payload).status_code == 400


# --- /auth/login/enroll/* (alta obligatoria) -------------------------------------------------------
@pytest.fixture
def enrolling(api, make_user):
    user = make_user(role="admin")
    assert api.login(user.email).json() == {"status": "mfa_enrollment_required"}
    return api, user


def test_enroll_setup_and_confirm(enrolling):
    client, user = enrolling
    body = _assert_setup(client.post("/auth/login/enroll/setup"))
    response = client.post("/auth/login/enroll/confirm", {"totp_code": totp_code(body["secret_base32"])})
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"status", "user", "recovery_codes"} and data["status"] == "authenticated"
    assert set(data["user"]) == USER_SUMMARY and data["user"]["mfa_enabled"] is True
    _assert_codes(data["recovery_codes"])
    assert session_cookie_set(response)
    assert response["Cache-Control"] == "no-store"
    assert client.get("/auth/session").status_code == 200


def test_enroll_confirm_wrong_code(enrolling):
    client, user = enrolling
    client.post("/auth/login/enroll/setup")
    response = client.post("/auth/login/enroll/confirm", {"totp_code": "000000"})
    assert response.status_code == 401
    assert response.json() == {"error": GENERIC_401}
    assert not TOTPDevice.objects.filter(user=user, status="active").exists()


def test_enroll_confirm_without_setup(enrolling):
    client, _ = enrolling
    assert client.post("/auth/login/enroll/confirm", {"totp_code": "123456"}).status_code == 401


# --- /users/{id}/mfa/totp/setup|confirm -----------------------------------------------------------
def test_self_service_setup_without_mfa_needs_no_password(login_as):
    client, _ = login_as("client")
    _assert_setup(client.post("/users/me/mfa/totp/setup", {}))


def test_self_service_setup_with_mfa_requires_password(login_as):
    client, user = login_as("client", mfa=True)
    missing = client.post("/users/me/mfa/totp/setup", {})
    assert missing.status_code == 400
    wrong = client.post("/users/me/mfa/totp/setup", {"password": "contraseña equivocada pero larga"})
    assert wrong.status_code == 400 and wrong.json()["error"]["code"] == "verification_failed"
    _assert_setup(client.post("/users/me/mfa/totp/setup", {"password": "correcto caballo batería grapa 2026"}))


def test_self_service_confirm_rotates_and_revokes_others(login_as):
    client, user = login_as("client")
    other, _ = login_as(user=user)
    body = client.post("/users/me/mfa/totp/setup", {}).json()
    old_key = client.session_cookie
    response = client.post("/users/me/mfa/totp/confirm", {"totp_code": totp_code(body["secret_base32"])})
    assert response.status_code == 200
    assert set(response.json()) == {"recovery_codes"}
    _assert_codes(response.json()["recovery_codes"])
    assert response["Cache-Control"] == "no-store"
    assert session_cookie_set(response) and client.session_cookie != old_key
    assert client.get("/auth/session").status_code == 200
    assert other.get("/auth/session").status_code == 401
    assert UserSession.objects.filter(user=user).count() == 1


def test_self_service_confirm_wrong_code(login_as):
    client, user = login_as("client")
    client.post("/users/me/mfa/totp/setup", {})
    response = client.post("/users/me/mfa/totp/confirm", {"totp_code": "000000"})
    assert response.status_code == 400 and response.json()["error"]["code"] == "verification_failed"
    assert not TOTPDevice.objects.filter(user=user, status="active").exists()


# --- /users/{id}/mfa/totp/disable -----------------------------------------------------------------
def test_client_disables_mfa(login_as):
    client, user = login_as("client", mfa=True)
    other, _ = login_as(user=user)
    response = client.post(
        "/users/me/mfa/totp/disable",
        {"password": "correcto caballo batería grapa 2026", "totp_code": totp_code(user.totp_secret, steps=1)},
    )
    assert response.status_code == 204
    assert not TOTPDevice.objects.filter(user=user).exists()
    assert session_cookie_set(response)
    assert other.get("/auth/session").status_code == 401
    assert client.get("/users/me/security").json()["mfa_enabled"] is False


@pytest.mark.parametrize(
    "payload",
    [{"password": "contraseña equivocada pero larga", "totp_code": "STEP"}, {"password": "correcto caballo batería grapa 2026", "totp_code": "000000"}],
)
def test_disable_requires_password_and_code(login_as, payload):
    client, user = login_as("client", mfa=True)
    payload = {**payload, "totp_code": totp_code(user.totp_secret, steps=1) if payload["totp_code"] == "STEP" else payload["totp_code"]}
    response = client.post("/users/me/mfa/totp/disable", payload)
    assert response.status_code == 400 and response.json()["error"]["code"] == "verification_failed"
    assert TOTPDevice.objects.filter(user=user, status="active").exists()


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_privileged_roles_cannot_disable(login_as, role):
    client, user = login_as(role)
    response = client.post(
        "/users/me/mfa/totp/disable",
        {"password": "correcto caballo batería grapa 2026", "totp_code": totp_code(user.totp_secret, steps=1)},
    )
    assert response.status_code == 403
    assert TOTPDevice.objects.filter(user=user, status="active").exists()


# --- /users/{id}/mfa/recovery-codes/regenerate ----------------------------------------------------
def test_regenerate_recovery_codes(login_as):
    client, user = login_as("client", mfa=True)
    old = recovery_codes.generate_batch(user)
    response = client.post(
        "/users/me/mfa/recovery-codes/regenerate",
        {"password": "correcto caballo batería grapa 2026", "totp_code": totp_code(user.totp_secret, steps=1)},
    )
    assert response.status_code == 200
    assert set(response.json()) == {"recovery_codes"}
    _assert_codes(response.json()["recovery_codes"])
    assert response["Cache-Control"] == "no-store"
    assert session_cookie_set(response)
    assert recovery_codes.consume(user, old[0]) is None


def test_regenerate_without_mfa_conflicts(login_as):
    client, _ = login_as("client")
    response = client.post(
        "/users/me/mfa/recovery-codes/regenerate",
        {"password": "correcto caballo batería grapa 2026", "totp_code": "123456"},
    )
    assert response.status_code == 409


def test_mfa_routes_reject_foreign_user(login_as):
    client, _ = login_as("client")
    _, other = login_as("client")
    for suffix in ("totp/setup", "totp/confirm", "totp/disable", "recovery-codes/regenerate"):
        assert client.post(f"/users/{other.id}/mfa/{suffix}", {}).status_code == 404
