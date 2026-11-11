"""TS-A03 (T071): escenarios de aceptación 1–10 de US3 (TOTP y códigos de recuperación)."""

from __future__ import annotations

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.models import RecoveryCode, TOTPDevice
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.acceptance


def _enable_mfa(client):
    secret = client.post("/users/me/mfa/totp/setup", {}).json()["secret_base32"]
    codes = client.post("/users/me/mfa/totp/confirm", {"totp_code": totp_code(secret)}).json()["recovery_codes"]
    return secret, codes


def test_us3_1_enable_totp_shows_codes_once(login_as):
    client, user = login_as("client")
    secret, codes = _enable_mfa(client)
    assert len(codes) == 10
    assert client.get("/users/me/security").json() == {
        "mfa_enabled": True, "mfa_required": False, "recovery_codes_remaining": 10
    }
    # No hay forma de volver a obtener los mismos códigos: solo existen sus verificadores.
    assert not any(code in v for code in codes for v in RecoveryCode.objects.values_list("verifier", flat=True))
    assert SecurityEvent.objects.filter(event_type="mfa_enabled", actor_id=user.id).exists()


def test_us3_2_unconfirmed_setup_does_not_enable_mfa(login_as):
    client, user = login_as("client")
    client.post("/users/me/mfa/totp/setup", {})
    client.post("/users/me/mfa/totp/confirm", {"totp_code": "000000"})
    assert not TOTPDevice.objects.filter(user=user, status="active").exists()
    assert not RecoveryCode.objects.filter(user=user).exists()
    assert client.get("/users/me/security").json()["mfa_enabled"] is False


def test_us3_3_password_and_valid_totp_grant_session(api, make_user):
    user = make_user()
    secret = make_totp_device(user)
    assert api.login(user.email).json() == {"status": "mfa_required"}
    assert api.get("/auth/session").status_code == 401
    assert api.post("/auth/login/mfa", {"totp_code": totp_code(secret)}).json()["status"] == "authenticated"
    assert api.get("/auth/session").status_code == 200


@pytest.mark.parametrize("kind", ["wrong", "expired", "reused"])
def test_us3_4_wrong_expired_or_reused_code_denied_and_counted(api_factory, make_user, kind):
    user = make_user()
    secret = make_totp_device(user)
    if kind == "reused":
        first = api_factory()
        first.login(user.email)
        code = totp_code(secret)
        assert first.post("/auth/login/mfa", {"totp_code": code}).status_code == 200
    else:
        code = "000000" if kind == "wrong" else totp_code(secret, steps=-3)
        if kind == "wrong" and code == totp_code(secret):
            code = "111111"
    client = api_factory()
    client.login(user.email)
    response = client.post("/auth/login/mfa", {"totp_code": code})
    assert response.status_code == 401
    assert client.get("/auth/session").status_code == 401
    failed = SecurityEvent.objects.filter(event_type="login_failed", actor_id=user.id, metadata__stage="mfa")
    assert failed.count() == 1


def test_us3_5_recovery_code_grants_session_and_reports_remaining(login_as, api_factory):
    client, user = login_as("client")
    _, codes = _enable_mfa(client)
    lost_device = api_factory()
    lost_device.login(user.email)
    response = lost_device.post("/auth/login/mfa", {"recovery_code": codes[0]})
    assert response.status_code == 200 and response.json()["recovery_codes_remaining"] == 9  # V12
    assert SecurityEvent.objects.filter(event_type="recovery_code_used", actor_id=user.id).exists()


@pytest.mark.parametrize("kind", ["used", "previous_batch"])
def test_us3_6_used_or_previous_batch_code_rejected(login_as, api_factory, kind):
    client, user = login_as("client")
    secret, codes = _enable_mfa(client)
    if kind == "used":
        first = api_factory()
        first.login(user.email)
        assert first.post("/auth/login/mfa", {"recovery_code": codes[0]}).status_code == 200
    else:
        client.post(
            "/users/me/mfa/recovery-codes/regenerate",
            {"password": STRONG_PASSWORD, "totp_code": totp_code(secret, steps=1)},
        )
    second = api_factory()
    second.login(user.email)
    assert second.post("/auth/login/mfa", {"recovery_code": codes[0]}).status_code == 401  # V12


def test_us3_7_regenerate_codes_requires_password_and_totp(login_as):
    client, user = login_as("client")
    secret, old = _enable_mfa(client)
    denied = client.post("/users/me/mfa/recovery-codes/regenerate", {"password": STRONG_PASSWORD, "totp_code": "000000"})
    assert denied.status_code == 400
    response = client.post(
        "/users/me/mfa/recovery-codes/regenerate", {"password": STRONG_PASSWORD, "totp_code": totp_code(secret, steps=1)}
    )
    new = response.json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(old)
    assert RecoveryCode.objects.filter(user=user, status="available").count() == 10
    assert RecoveryCode.objects.filter(user=user, status="invalidated").count() == 10
    assert SecurityEvent.objects.filter(event_type="recovery_codes_regenerated", actor_id=user.id).exists()


def test_us3_8_reconfigure_after_recovery_login(login_as, api_factory):
    owner, user = login_as("client")
    old_secret, old_codes = _enable_mfa(owner)
    client = api_factory()
    client.login(user.email)
    assert client.post("/auth/login/mfa", {"recovery_code": old_codes[0]}).status_code == 200
    setup = client.post("/users/me/mfa/totp/setup", {"password": STRONG_PASSWORD}).json()
    confirm = client.post("/users/me/mfa/totp/confirm", {"totp_code": totp_code(setup["secret_base32"])})
    assert confirm.status_code == 200
    new_codes = confirm.json()["recovery_codes"]
    assert SecurityEvent.objects.filter(event_type="mfa_reconfigured", actor_id=user.id).exists()
    # El secreto y los códigos anteriores ya no sirven.
    retry = api_factory()
    retry.login(user.email)
    assert retry.post("/auth/login/mfa", {"totp_code": totp_code(old_secret, steps=1)}).status_code == 401
    assert retry.post("/auth/login/mfa", {"recovery_code": old_codes[1]}).status_code == 401
    assert retry.post("/auth/login/mfa", {"recovery_code": new_codes[0]}).status_code == 200


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_us3_9_privileged_without_mfa_can_only_enroll(api, make_user, role):
    user = make_user(role=role)
    assert api.login(user.email).json() == {"status": "mfa_enrollment_required"}
    for path in ("/auth/session", "/users/me/profile", "/users/me/security"):
        assert api.get(path).status_code == 401  # V10
    secret = api.post("/auth/login/enroll/setup").json()["secret_base32"]
    confirm = api.post("/auth/login/enroll/confirm", {"totp_code": totp_code(secret)})
    assert confirm.status_code == 200 and len(confirm.json()["recovery_codes"]) == 10
    assert api.get("/users/me/profile").status_code == 200


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_us3_10_privileged_cannot_disable(login_as, role):
    client, user = login_as(role)
    response = client.post(
        "/users/me/mfa/totp/disable", {"password": STRONG_PASSWORD, "totp_code": totp_code(user.totp_secret, steps=1)}
    )
    assert response.status_code == 403
    assert TOTPDevice.objects.filter(user=user, status="active").exists()


def test_us3_10_client_can_disable(login_as):
    client, user = login_as("client")
    secret, _ = _enable_mfa(client)
    response = client.post(
        "/users/me/mfa/totp/disable", {"password": STRONG_PASSWORD, "totp_code": totp_code(secret, steps=1)}
    )
    assert response.status_code == 204
    assert not RecoveryCode.objects.filter(user=user, status="available").exists()
    assert SecurityEvent.objects.filter(event_type="mfa_disabled", actor_id=user.id).exists()
