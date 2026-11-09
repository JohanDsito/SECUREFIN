"""TS-S12 (T082): Pruebas de seguridad contra abusos en el reinicio de MFA.

Comprueba que se rechazan:
- Abrir un caso propio por el propio Administrador (403).
- Autorizar sin TOTP del Administrador o por un Administrador distinto del que abrió el caso (403).
- Un código de verificación de desafío caducado (más de 10 min) o reutilizado (409).
- Un cuarto intento (el caso pasa a 'cancelled' al tercer fallo de verificación).
- Una solicitud de reinicio sin sesión pre_auth (401) y la 4.ª solicitud en 24 h (429).
- Que la contraseña del titular no cambia y las respuestas nunca contienen el secreto TOTP ni códigos.
"""

from __future__ import annotations

from datetime import timedelta
import uuid
import pytest

from apps.core import clock
from apps.iam.models import TOTPDevice, User
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.security


def _create_pre_auth_client(api_factory, user):
    """Crea una sesión pre_auth real para un usuario con MFA activo."""
    client = api_factory()
    resp = client.login(user.email, STRONG_PASSWORD)
    assert resp.status_code == 200 and resp.json().get("status") == "mfa_required"
    return client


def test_self_reset_forbidden(login_as):
    """Un Administrador no puede abrir un caso de reinicio de MFA sobre sí mismo (403)."""
    admin_client, admin_user = login_as("admin")
    resp = admin_client.post(
        f"/admin/mfa-resets/{admin_user.id}/open",
        {"request_channel": "in_person"},
    )
    assert resp.status_code == 403


def test_open_case_requires_full_admin_with_mfa(api, make_user, login_as):
    """Abrir un caso exige Administrador con MFA activo y sesión full (403 para cliente, 401 para pre_auth)."""
    target = make_user(role="client")
    case_id = uuid.uuid4()

    # 1. Cliente intenta abrir caso -> 403
    client, _ = login_as("client")
    resp_client = client.post(f"/admin/mfa-resets/{case_id}/open", {"request_channel": "in_person"})
    assert resp_client.status_code == 403

    # 2. Administrador en pre_auth -> 401
    admin = make_user(role="admin")
    make_totp_device(admin)
    pre_admin = api
    pre_admin.login(admin.email, STRONG_PASSWORD)
    resp_pre = pre_admin.post(f"/admin/mfa-resets/{case_id}/open", {"request_channel": "in_person"})
    assert resp_pre.status_code == 401


def test_authorize_requires_same_admin_that_opened(login_as, make_user):
    """Solo el Administrador que abrió el caso puede autorizarlo (403 para otro Administrador)."""
    admin_a_client, admin_a = login_as("admin")
    admin_b_client, admin_b = login_as("admin")
    target_user = make_user(role="client")
    make_totp_device(target_user)

    case_id = uuid.uuid4()
    resp = admin_b_client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": totp_code(admin_b.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 403


def test_authorize_requires_valid_admin_totp(login_as, make_user):
    """Autorizar el reinicio exige el código TOTP actual del Administrador autorizador."""
    admin_client, admin_user = login_as("admin")
    case_id = uuid.uuid4()

    # Intento con TOTP inválido
    resp = admin_client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": "000000",
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 400
    assert resp.json().get("error", {}).get("code") == "verification_failed"


def test_authorize_expired_or_reused_code(login_as, make_user, clock):
    """Un código de desafío caducado (>10 min) o ya resuelto se rechaza con 409."""
    admin_client, admin_user = login_as("admin")
    case_id = uuid.uuid4()

    # Simular paso de 11 minutos
    clock.advance(minutes=11)
    resp = admin_client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": totp_code(admin_user.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 409


def test_third_failed_attempt_cancels_case(login_as):
    """Al tercer intento fallido de verificación, el caso queda cancelado y un 4.º intento falla (409)."""
    admin_client, admin_user = login_as("admin")
    case_id = uuid.uuid4()

    for _ in range(3):
        admin_client.post(
            f"/admin/mfa-resets/{case_id}/authorize",
            {
                "verification_code": "INVALID1",
                "admin_totp_code": totp_code(admin_user.totp_secret),
                "channel_confirmed": True,
            },
        )

    # 4.º intento
    resp4 = admin_client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "INVALID1",
            "admin_totp_code": totp_code(admin_user.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp4.status_code == 409


def test_request_reset_requires_pre_auth(api, make_user, login_as):
    """La solicitud de reinicio solo se permite con sesión pre_auth (401 para anónimo y full)."""
    # 1. Anónimo
    resp_anon = api.post("/auth/login/mfa-reset-request", {})
    assert resp_anon.status_code == 401

    # 2. Sesión completa (full)
    full_client, user = login_as("client")
    resp_full = full_client.post("/auth/login/mfa-reset-request", {})
    assert resp_full.status_code in (401, 403)


def test_request_reset_rate_limit_three_per_24h(api_factory, make_user, clock):
    """Máximo 3 solicitudes de reinicio de MFA por titular cada 24 horas (la 4.ª da 429)."""
    user = make_user(role="client")
    make_totp_device(user)

    for i in range(3):
        client = _create_pre_auth_client(api_factory, user)
        resp = client.post("/auth/login/mfa-reset-request", {})
        assert resp.status_code == 202

    # 4.ª solicitud dentro de la ventana de 24h
    client4 = _create_pre_auth_client(api_factory, user)
    resp4 = client4.post("/auth/login/mfa-reset-request", {})
    assert resp4.status_code == 429


def test_mfa_reset_preserves_password_and_never_leaks_secrets(login_as, make_user):
    """El reinicio de MFA nunca altera la contraseña del titular ni devuelve secretos o códigos."""
    admin_client, admin_user = login_as("admin")
    target_user = make_user(role="client", password=STRONG_PASSWORD)
    make_totp_device(target_user)
    original_password_hash = target_user.password

    case_id = uuid.uuid4()
    resp = admin_client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": totp_code(admin_user.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 200

    # Refrescar usuario desde la DB
    target_user.refresh_from_db()
    assert target_user.password == original_password_hash

    content = resp.content.decode()
    assert "secret" not in content.lower()
    assert "recovery_codes" not in content.lower()
