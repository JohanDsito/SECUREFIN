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

import itertools
import uuid

import pytest
from django.core import mail

from apps.audit.models import SecurityEvent
from apps.iam.models import MfaResetCase, MfaResetStatus, TOTPDevice
from apps.iam.services import mfa_reset, outbox
from tests.conftest import STRONG_PASSWORD
from tests.helpers import fresh_totp, make_totp_device, opened_case, requested_case

pytestmark = pytest.mark.security


_ips = itertools.count(1)


def _create_pre_auth_client(api_factory, user):
    """Crea una sesión pre_auth real para un usuario con MFA activo.

    Cada cliente sale de una IP distinta: así estas pruebas validan las reglas POR TITULAR
    (idempotencia, 3 casos en 24 h) sin que las tape el límite por IP de T101 (3/día).
    """
    client = api_factory(ip=f"198.51.100.{next(_ips) % 250 + 1}")
    resp = client.login(user.email, STRONG_PASSWORD)
    assert resp.status_code == 200 and resp.json().get("status") == "mfa_required"
    return client


def _authorize(client, case_id, code, totp):
    return client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {"verification_code": code, "admin_totp_code": totp, "channel_confirmed": True},
    )


def test_self_reset_forbidden(login_as, api_factory):
    """Un Administrador no puede abrir un caso de reinicio de MFA sobre sí mismo (403)."""
    admin_client, admin_user = login_as("admin")
    # El propio Administrador solicita el reinicio desde otra sesión pre_auth...
    pre = _create_pre_auth_client(api_factory, admin_user)
    assert pre.post("/auth/login/mfa-reset-request", {}).status_code == 202
    case = MfaResetCase.objects.get(target_user=admin_user, status=MfaResetStatus.REQUESTED)

    # ...y con una sesión full nueva intenta abrirlo, autorizarlo o cancelarlo él mismo.
    admin_client, _ = login_as("admin", user=admin_user)
    resp = admin_client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "self_action_forbidden"
    assert admin_client.post(f"/admin/mfa-resets/{case.id}/cancel", {}).status_code == 403
    case.refresh_from_db()
    assert case.status == MfaResetStatus.REQUESTED
    assert SecurityEvent.objects.filter(
        event_type="authz_denied", actor_id=admin_user.id, metadata__reason="self_action"
    ).exists()


def test_open_case_requires_full_admin_with_mfa(api, make_user, login_as):
    """Abrir un caso exige Administrador con MFA activo y sesión full (403 cliente/auditor, 401 pre_auth)."""
    case = requested_case(make_user(role="client"))

    for role in ("client", "auditor"):
        client, _ = login_as(role)
        resp = client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
        assert resp.status_code == 403

    admin = make_user(role="admin")
    make_totp_device(admin)
    api.login(admin.email, STRONG_PASSWORD)  # se queda en pre_auth
    resp_pre = api.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    assert resp_pre.status_code == 401

    case.refresh_from_db()
    assert case.status == MfaResetStatus.REQUESTED


def test_authorize_requires_same_admin_that_opened(login_as, make_user):
    """Solo el Administrador que abrió el caso puede autorizarlo (403 para otro Administrador)."""
    _, admin_a = login_as("admin")
    admin_b_client, admin_b = login_as("admin")
    case, code = opened_case(admin_a, make_user(role="client"))

    resp = _authorize(admin_b_client, case.id, code, fresh_totp(admin_b))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "not_case_owner"
    case.refresh_from_db()
    assert case.status == MfaResetStatus.PENDING_VERIFICATION
    assert case.challenge_attempts == 0  # un tercero no consume intentos del caso


def test_authorize_requires_valid_admin_totp(login_as, make_user):
    """Autorizar exige el TOTP actual del Administrador: con el código correcto pero sin TOTP → 400."""
    admin_client, admin_user = login_as("admin")
    target = make_user(role="client")
    case, code = opened_case(admin_user, target)

    resp = _authorize(admin_client, case.id, code, "000000")
    assert resp.status_code == 400
    assert resp.json().get("error", {}).get("code") == "verification_failed"
    case.refresh_from_db()
    assert case.status == MfaResetStatus.PENDING_VERIFICATION and case.challenge_attempts == 1
    assert TOTPDevice.objects.filter(user=target).exists()  # sin efectos


def test_authorize_rejects_replayed_admin_totp(login_as, make_user):
    """El TOTP que el Administrador acaba de usar en su login no sirve para autorizar (antirrepetición)."""
    from tests.helpers import totp_code

    admin_client, admin_user = login_as("admin")
    case, code = opened_case(admin_user, make_user(role="client"))
    resp = _authorize(admin_client, case.id, code, totp_code(admin_user.totp_secret))
    assert resp.status_code == 400


def test_authorize_expired_code(login_as, make_user, clock):
    """Un código de desafío caducado (>10 min desde la entrega) se rechaza con 409 y el caso expira."""
    admin_client, admin_user = login_as("admin")
    case, code = opened_case(admin_user, make_user(role="client"))

    clock.advance(minutes=11)
    resp = _authorize(admin_client, case.id, code, fresh_totp(admin_user))
    assert resp.status_code == 409
    case.refresh_from_db()
    assert case.status == MfaResetStatus.EXPIRED and case.challenge_verifier is None


def test_authorize_reused_code(login_as, make_user):
    """Un código ya usado no vale una segunda vez: el caso ya está resuelto (409)."""
    admin_client, admin_user = login_as("admin")
    case, code = opened_case(admin_user, make_user(role="client"))
    assert _authorize(admin_client, case.id, code, fresh_totp(admin_user)).status_code == 200
    assert _authorize(admin_client, case.id, code, fresh_totp(admin_user)).status_code == 409


def test_code_from_another_case_is_rejected(login_as, make_user):
    """Un código solo vale para su caso."""
    admin_client, admin_user = login_as("admin")
    case_a, _ = opened_case(admin_user, make_user(role="client"))
    _, code_b = opened_case(admin_user, make_user(role="client"))
    assert _authorize(admin_client, case_a.id, code_b, fresh_totp(admin_user)).status_code == 400


def test_third_failed_attempt_cancels_case(login_as, make_user):
    """Al tercer intento fallido el caso queda cancelado (con evento) y un 4.º intento falla (409)."""
    admin_client, admin_user = login_as("admin")
    target = make_user(role="client")
    case, code = opened_case(admin_user, target)

    for _ in range(3):
        assert _authorize(admin_client, case.id, "INVALID1", fresh_totp(admin_user)).status_code == 400

    case.refresh_from_db()
    assert case.status == MfaResetStatus.CANCELLED and case.challenge_verifier is None
    assert SecurityEvent.objects.filter(
        event_type="mfa_reset_cancelled", target_id=target.id, metadata__reason="max_attempts"
    ).exists()

    # 4.º intento, incluso con el código correcto
    assert _authorize(admin_client, case.id, code, fresh_totp(admin_user)).status_code == 409
    assert TOTPDevice.objects.filter(user=target).exists()


def test_request_reset_requires_pre_auth(api, make_user, login_as):
    """La solicitud de reinicio solo se permite con sesión pre_auth (401 para anónimo y full)."""
    resp_anon = api.post("/auth/login/mfa-reset-request", {})
    assert resp_anon.status_code == 401

    full_client, user = login_as("client", mfa=True)
    resp_full = full_client.post("/auth/login/mfa-reset-request", {})
    assert resp_full.status_code == 401
    assert not MfaResetCase.objects.filter(target_user=user).exists()


def test_request_reset_requires_active_mfa(api_factory, make_user):
    """En el alta obligatoria (pre_auth sin MFA activo) no hay nada que reiniciar → 401."""
    auditor = make_user(role="auditor")
    client = api_factory()
    assert client.login(auditor.email).json()["status"] == "mfa_enrollment_required"
    assert client.post("/auth/login/mfa-reset-request", {}).status_code == 401
    assert not MfaResetCase.objects.filter(target_user=auditor).exists()


def test_request_reset_closes_pre_auth_session(api_factory, make_user):
    """La solicitud cierra la sesión pre_auth: no se puede seguir con el segundo paso."""
    user = make_user(role="client")
    make_totp_device(user)
    client = _create_pre_auth_client(api_factory, user)
    assert client.post("/auth/login/mfa-reset-request", {}).status_code == 202
    assert client.post("/auth/login/mfa", {"totp_code": "123456"}).status_code == 401


def test_request_reset_is_idempotent_while_open(api_factory, make_user):
    user = make_user(role="client")
    make_totp_device(user)
    for _ in range(4):
        client = _create_pre_auth_client(api_factory, user)
        assert client.post("/auth/login/mfa-reset-request", {}).status_code == 202
    assert MfaResetCase.objects.filter(target_user=user).count() == 1


def test_request_reset_rate_limit_three_per_24h(api_factory, make_user, login_as):
    """Máximo 3 solicitudes (casos) por titular cada 24 h: la 4.ª da 429 con Retry-After."""
    user = make_user(role="client")
    make_totp_device(user)
    admin_client, _ = login_as("admin")

    for _ in range(3):
        client = _create_pre_auth_client(api_factory, user)
        assert client.post("/auth/login/mfa-reset-request", {}).status_code == 202
        case = MfaResetCase.objects.get(target_user=user, status=MfaResetStatus.REQUESTED)
        assert admin_client.post(f"/admin/mfa-resets/{case.id}/cancel", {}).status_code == 204

    client4 = _create_pre_auth_client(api_factory, user)
    resp4 = client4.post("/auth/login/mfa-reset-request", {})
    assert resp4.status_code == 429
    assert int(resp4.headers["Retry-After"]) > 0
    assert MfaResetCase.objects.filter(target_user=user).count() == 3


def test_challenge_not_sent_for_cancelled_case(login_as, make_user):
    """Si el caso se cancela antes de entregar el desafío, nunca se genera ni se envía el código."""
    _, admin = login_as("admin")
    target = make_user(role="client")
    case = requested_case(target)
    mfa_reset.open_case(admin, case.id, "in_person")
    mfa_reset.cancel(admin, case.id)

    outbox.deliver_due()
    assert not [m for m in mail.outbox if m.to == [target.email]]
    case.refresh_from_db()
    assert case.challenge_verifier is None


def test_mfa_reset_preserves_password_and_never_leaks_secrets(login_as, make_user):
    """El reinicio de MFA nunca altera la contraseña del titular ni devuelve secretos o códigos."""
    admin_client, admin_user = login_as("admin")
    target_user = make_user(role="client", password=STRONG_PASSWORD)
    original_password_hash = target_user.password
    case, code = opened_case(admin_user, target_user)

    resp = _authorize(admin_client, case.id, code, fresh_totp(admin_user))
    assert resp.status_code == 200

    target_user.refresh_from_db()
    assert target_user.password == original_password_hash

    content = resp.content.decode().lower()
    assert "secret" not in content
    assert "recovery_codes" not in content
    assert code.lower() not in content
    listing = admin_client.get("/admin/mfa-resets").content.decode().lower()
    assert "verifier" not in listing and code.lower() not in listing


def test_unknown_case_id_is_404(login_as):
    client, admin = login_as("admin")
    resp = _authorize(client, uuid.uuid4(), "ABCDEFGH", fresh_totp(admin))
    assert resp.status_code == 404
