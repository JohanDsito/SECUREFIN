"""TS-S03 (revisión de seguridad de US3): ningún secreto TOTP ni código sale de donde debe.

- El secreto solo aparece en la respuesta de alta; nunca en otras respuestas, logs ni auditoría.
- Los códigos de recuperación solo aparecen en la respuesta que los genera.
- Un cambio de identidad entre `setup` y `confirm` no activa nada.
- Un texto cifrado trasplantado o alterado en la base falla de forma cerrada (401/400, nunca 500).
"""

from __future__ import annotations

import logging

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.models import TOTPDevice
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.security


def _all_logs(caplog) -> str:
    return "\n".join(f"{r.getMessage()} {r.args!r} {getattr(r, 'exc_text', '')}" for r in caplog.records)


def test_secret_and_codes_only_in_their_own_responses(login_as, caplog):
    caplog.set_level(logging.DEBUG)
    client, user = login_as("client")
    setup = client.post("/users/me/mfa/totp/setup", {})
    secret = setup.json()["secret_base32"]
    code = totp_code(secret)
    confirm = client.post("/users/me/mfa/totp/confirm", {"totp_code": code})
    codes = confirm.json()["recovery_codes"]
    assert secret not in confirm.content.decode()

    others = [client.get(p) for p in ("/users/me/profile", "/users/me/security", "/users/me/sessions", "/auth/session")]
    for response in others:
        body = response.content.decode()
        assert secret not in body and not any(c in body for c in codes)

    logs = _all_logs(caplog)
    assert secret not in logs and code not in logs and not any(c in logs for c in codes)
    metadata = " ".join(str(e.metadata) for e in SecurityEvent.objects.all())
    assert secret not in metadata and not any(c in metadata for c in codes)


def test_login_mfa_never_logs_codes(api_factory, make_user, caplog):
    caplog.set_level(logging.DEBUG)
    user = make_user()
    secret = make_totp_device(user)
    client = api_factory()
    client.login(user.email)
    good = totp_code(secret)
    client.post("/auth/login/mfa", {"totp_code": "000000" if good != "000000" else "111111"})
    client.post("/auth/login/mfa", {"recovery_code": "ABCD" * 7})
    client.post("/auth/login/mfa", {"totp_code": good})
    logs = _all_logs(caplog)
    assert good not in logs and "ABCD" * 7 not in logs and secret not in logs


def test_identity_change_between_setup_and_confirm(login_as, api_factory):
    """A inicia el alta; en el mismo navegador entra B y confirma con el código de A: nada se activa."""
    client_a, user_a = login_as("client")
    secret_a = client_a.post("/users/me/mfa/totp/setup", {}).json()["secret_base32"]
    _, user_b = login_as("client")
    client_a.post("/auth/logout")
    client_a.login(user_b.email)  # mismo cliente HTTP, otra identidad
    response = client_a.post("/users/me/mfa/totp/confirm", {"totp_code": totp_code(secret_a)})
    assert response.status_code == 400
    assert not TOTPDevice.objects.filter(status="active").exists()
    assert TOTPDevice.objects.get(user=user_a).status == "pending"


def test_setup_and_confirm_require_full_session(api, make_user, db):
    for path in ("/users/me/mfa/totp/setup", "/users/me/mfa/totp/confirm"):
        assert api.post(path, {}).status_code == 401
    user = make_user()
    make_totp_device(user)
    api.login(user.email)  # pre_auth
    for path in ("/users/me/mfa/totp/setup", "/users/me/mfa/totp/confirm"):
        assert api.post(path, {"password": STRONG_PASSWORD}).status_code == 401


def test_transplanted_ciphertext_fails_closed(api_factory, make_user):
    """Copiar el secreto cifrado de A a la fila de B no permite entrar como B (AAD) ni produce un 500."""
    user_a, user_b = make_user(), make_user()
    secret_a = make_totp_device(user_a)
    make_totp_device(user_b)
    device_a = TOTPDevice.objects.get(user=user_a)
    TOTPDevice.objects.filter(user=user_b).update(
        secret_ciphertext=bytes(device_a.secret_ciphertext), nonce=bytes(device_a.nonce)
    )
    client = api_factory()
    client.login(user_b.email)
    response = client.post("/auth/login/mfa", {"totp_code": totp_code(secret_a)})
    assert response.status_code == 401
    assert client.get("/auth/session").status_code == 401
    assert SecurityEvent.objects.filter(
        event_type="totp_rejected", actor_id=user_b.id, metadata__reason="decryption_failed"
    ).exists()


def test_tampered_pending_ciphertext_fails_closed(login_as):
    client, user = login_as("client")
    secret = client.post("/users/me/mfa/totp/setup", {}).json()["secret_base32"]
    pending = TOTPDevice.objects.get(user=user, status="pending")
    tampered = bytes([pending.secret_ciphertext[0] ^ 1]) + bytes(pending.secret_ciphertext)[1:]
    TOTPDevice.objects.filter(pk=pending.pk).update(secret_ciphertext=tampered)
    response = client.post("/users/me/mfa/totp/confirm", {"totp_code": totp_code(secret)})
    assert response.status_code == 400
    assert not TOTPDevice.objects.filter(user=user, status="active").exists()
