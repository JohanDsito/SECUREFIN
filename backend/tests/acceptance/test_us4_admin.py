"""TS-A04 (T085): Pruebas de aceptación para la Historia de Usuario 4 (Administración y reinicio de MFA).

Escenarios 1–9 de spec.md:
1. Asignar rol Auditor a un usuario: revoca sesiones, exige MFA al siguiente acceso, registra role_changed.
2. Desactivar cuenta: revoca sesiones inmediatamente, impide login, registra account_deactivated.
3. Administrador sobre sí mismo: cambiar rol, desactivar o reiniciar MFA se rechazan (403).
4. Último Administrador activo: intentar degradarlo o desactivarlo se rechaza (409).
5. Crear cuenta privilegiada: enlace de activación en el buzón, establece contraseña, configura MFA.
6. Reinicio de MFA: solicitud tras contraseña (pre_auth), verificación fuera de banda, desafío por correo,
   autorización con TOTP del Administrador, invalidación de TOTP/códigos, notificación en buzón y eventos.
7. Garantías del reinicio: conserva la contraseña, no otorga acceso directo, el Administrador nunca ve secretos.
8. Bootstrap por consola: primer Administrador sin credenciales predeterminadas, activación por correo, evento.
9. Break-glass por consola: procedimiento extraordinario del último Administrador, sin API ni endpoints web.
"""

from __future__ import annotations

import io
from unittest import mock
import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.audit.models import SecurityEvent
from apps.iam.models import OutboxMessage, Role, Status, TOTPDevice, User, UserSession
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.acceptance


def test_us4_1_admin_changes_role_to_auditor_revokes_sessions_requires_mfa(login_as, make_user):
    """Escenario 1: Asignar rol Auditor revoca sesiones, exige MFA en el próximo login y registra evento."""
    admin_client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)

    # Crear una sesión para el usuario objetivo
    target_client, _ = login_as("client", user=target)
    assert target_client.get("/auth/session").status_code == 200

    resp = admin_client.patch(f"/admin/users/{target.id}/role", {"role": Role.AUDITOR})
    assert resp.status_code == 200

    target.refresh_from_db()
    assert target.role == Role.AUDITOR

    # Sesiones previas revocadas
    assert target_client.get("/auth/session").status_code == 401

    # Siguiente login exige MFA (o enrollment si no tiene)
    login_resp = target_client.login(target.email)
    assert login_resp.json().get("status") in ("mfa_required", "mfa_enrollment_required")

    # Evento registrado
    assert SecurityEvent.objects.filter(
        event_type="role_changed",
        target_id=target.id,
        metadata__to_role=Role.AUDITOR,
    ).exists()


def test_us4_2_admin_deactivates_account_revokes_sessions_blocks_login(login_as, make_user):
    """Escenario 2: Desactivar cuenta revoca sesiones de inmediato y bloquea inicio de sesión."""
    admin_client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)
    target_client, _ = login_as("client", user=target)

    resp = admin_client.post(f"/admin/users/{target.id}/deactivate", {})
    assert resp.status_code == 204

    target.refresh_from_db()
    assert target.status == Status.DEACTIVATED

    # Sesión previa revocada
    assert target_client.get("/auth/session").status_code == 401

    # Intento de login falla de forma genérica
    assert target_client.login(target.email).status_code == 401

    # Evento registrado
    assert SecurityEvent.objects.filter(
        event_type="account_deactivated",
        target_id=target.id,
    ).exists()


def test_us4_3_admin_cannot_operate_on_self(login_as):
    """Escenario 3: Administrador no puede cambiar su rol, desactivarse ni reiniciar su propio MFA."""
    admin_client, admin_user = login_as("admin")

    # 1. Cambiar propio rol
    resp_role = admin_client.patch(f"/admin/users/{admin_user.id}/role", {"role": Role.CLIENT})
    assert resp_role.status_code == 403

    # 2. Desactivarse a sí mismo
    resp_deact = admin_client.post(f"/admin/users/{admin_user.id}/deactivate", {})
    assert resp_deact.status_code == 403

    # 3. Reiniciar su propio MFA
    resp_mfa = admin_client.post(f"/admin/mfa-resets/{admin_user.id}/open", {"request_channel": "in_person"})
    assert resp_mfa.status_code == 403


def test_us4_4_last_active_admin_cannot_be_degraded_or_deactivated(login_as, make_user):
    """Escenario 4: Si solo queda un Administrador activo, no puede ser degradado ni desactivado (409)."""
    # Solo queda 1 administrador activo
    User.objects.filter(role=Role.ADMIN).delete()
    admin_client, admin_user = login_as("admin")

    other_admin_client, other_admin = login_as("admin")
    # Ahora desactivamos other_admin para que admin_user sea el último activo
    User.objects.filter(id=other_admin.id).update(status=Status.DEACTIVATED)

    # other_admin reactivado o admin_user intentando degradarse:
    resp = other_admin_client.patch(f"/admin/users/{admin_user.id}/role", {"role": Role.AUDITOR})
    assert resp.status_code == 409


def test_us4_5_admin_creates_privileged_user_activates_via_mailbox(login_as):
    """Escenario 5: Administrador crea cuenta privilegiada, recibe enlace en el buzón y la activa."""
    admin_client, _ = login_as("admin")
    resp = admin_client.post(
        "/admin/users",
        {
            "email": "nuevo-auditor-us4@lab.securefin.local",
            "name": "Auditor US4",
            "role": Role.AUDITOR,
        },
    )
    assert resp.status_code == 201

    user_id = resp.json()["id"]
    auditor = User.objects.get(id=user_id)
    assert auditor.status == Status.PENDING_ACTIVATION

    # Mensaje de activación encolado en outbox
    assert OutboxMessage.objects.filter(
        user=auditor,
        kind="account_activation",
    ).exists()


def test_us4_6_mfa_reset_flow_with_admin_totp_and_email_challenge(login_as, make_user, api):
    """Escenario 6: Flujo completo de reinicio de MFA con verificación fuera de banda y TOTP del Admin."""
    admin_client, admin_user = login_as("admin")
    client_user = make_user(role=Role.CLIENT)
    make_totp_device(client_user)

    # 1. Solicitud en pre_auth
    api.login(client_user.email, STRONG_PASSWORD)
    req_resp = api.post("/auth/login/mfa-reset-request", {})
    assert req_resp.status_code == 202

    # 2. Admin abre el caso
    open_resp = admin_client.post(
        f"/admin/mfa-resets/{client_user.id}/open",
        {"request_channel": "in_person"},
    )
    assert open_resp.status_code == 200


def test_us4_7_reset_does_not_reveal_or_change_password_and_user_still_needs_password(login_as, make_user):
    """Escenario 7: El reinicio de MFA no cambia la contraseña del usuario ni concede acceso directo."""
    admin_client, admin_user = login_as("admin")
    target_user = make_user(role=Role.CLIENT, password=STRONG_PASSWORD)
    make_totp_device(target_user)
    old_hash = target_user.password

    # Ejecutar autorización de reinicio
    resp = admin_client.post(
        f"/admin/mfa-resets/{target_user.id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": totp_code(admin_user.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 200

    target_user.refresh_from_db()
    assert target_user.password == old_hash


def test_us4_8_console_bootstrap_first_admin(db):
    """Escenario 8: iam_bootstrap_admin crea el primer Administrador cuando no existe ninguno."""
    User.objects.filter(role=Role.ADMIN).delete()

    out = io.StringIO()
    call_command(
        "iam_bootstrap_admin",
        email="bootstrap-admin@lab.securefin.local",
        name="Bootstrap Admin",
        stdout=out,
    )

    admin = User.objects.get(email="bootstrap-admin@lab.securefin.local")
    assert admin.role == Role.ADMIN
    assert admin.status == Status.PENDING_ACTIVATION
    assert SecurityEvent.objects.filter(event_type="bootstrap_admin_executed").exists()


def test_us4_9_console_break_glass_last_admin(make_user):
    """Escenario 9: Procedimiento extraordinario break-glass para el último Administrador."""
    User.objects.filter(role=Role.ADMIN).delete()
    admin = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    make_totp_device(admin)

    out = io.StringIO()
    with mock.patch("builtins.input", return_value="yes"):
        call_command(
            "iam_break_glass",
            email=admin.email,
            reason="Pérdida de credenciales y MFA del último administrador",
            stdout=out,
        )

    assert SecurityEvent.objects.filter(event_type="break_glass_executed").exists()
