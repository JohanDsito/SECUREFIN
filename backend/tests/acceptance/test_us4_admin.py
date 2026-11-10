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
import re
from unittest import mock

import pytest
from django.core import mail
from django.core.management import call_command

from apps.audit.models import SecurityEvent
from apps.iam.models import (
    MfaResetCase,
    MfaResetStatus,
    OutboxMessage,
    RecoveryCode,
    RecoveryCodeStatus,
    Role,
    Status,
    TOTPDevice,
    User,
    UserSession,
)
from apps.iam.services import admin_users, outbox, recovery_codes
from tests.conftest import STRONG_PASSWORD
from tests.helpers import deliver_challenge_code, fresh_totp, make_totp_device, requested_case

pytestmark = pytest.mark.acceptance

_TOKEN_RE = re.compile(r"https://securefin\.local/activate#token=([A-Za-z0-9_-]+)")


def test_us4_1_admin_changes_role_to_auditor_revokes_sessions_requires_mfa(login_as, make_user):
    """Escenario 1: Asignar rol Auditor revoca sesiones, exige MFA en el próximo login y registra evento."""
    admin_client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)

    target_client, _ = login_as("client", user=target)
    assert target_client.get("/auth/session").status_code == 200

    resp = admin_client.patch(f"/admin/users/{target.id}/role", {"role": Role.AUDITOR})
    assert resp.status_code == 200

    target.refresh_from_db()
    assert target.role == Role.AUDITOR
    assert target_client.get("/auth/session").status_code == 401

    login_resp = target_client.login(target.email)
    assert login_resp.json().get("status") == "mfa_enrollment_required"

    assert SecurityEvent.objects.filter(
        event_type="role_changed", target_id=target.id, metadata__to_role=Role.AUDITOR
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
    assert target_client.get("/auth/session").status_code == 401
    assert target_client.login(target.email).status_code == 401
    assert SecurityEvent.objects.filter(event_type="account_deactivated", target_id=target.id).exists()


def test_us4_3_admin_cannot_operate_on_self(login_as, api_factory):
    """Escenario 3: Administrador no puede cambiar su rol, desactivarse ni reiniciar su propio MFA."""
    admin_client, admin_user = login_as("admin")

    resp_role = admin_client.patch(f"/admin/users/{admin_user.id}/role", {"role": Role.CLIENT})
    assert resp_role.status_code == 403
    resp_deact = admin_client.post(f"/admin/users/{admin_user.id}/deactivate", {})
    assert resp_deact.status_code == 403

    # Reiniciar su propio MFA: solicita desde pre_auth y, ya con sesión full, intenta abrir su caso.
    pre = api_factory()
    assert pre.login(admin_user.email).json()["status"] == "mfa_required"
    assert pre.post("/auth/login/mfa-reset-request", {}).status_code == 202
    case = MfaResetCase.objects.get(target_user=admin_user)
    admin_client, _ = login_as("admin", user=admin_user)
    resp_mfa = admin_client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    assert resp_mfa.status_code == 403

    admin_user.refresh_from_db()
    assert admin_user.role == Role.ADMIN and admin_user.status == Status.ACTIVE
    assert TOTPDevice.objects.filter(user=admin_user, status="active").exists()


def test_us4_4_last_active_admin_cannot_be_degraded_or_deactivated(login_as, make_user):
    """Escenario 4: con un solo Administrador activo, degradarlo o desactivarlo se rechaza (409).

    Por la API, cualquier actor válido es un Administrador activo distinto del objetivo, así que la
    situación solo se da en una carrera: B degrada a A mientras A degrada a B. Se reproduce de forma
    determinista con el actor ya desactualizado; la carrera real está en test_admin_and_console.
    """
    User.objects.filter(role=Role.ADMIN).delete()
    admin_a_client, admin_a = login_as("admin")
    _, admin_b = login_as("admin")

    assert admin_a_client.patch(f"/admin/users/{admin_b.id}/role", {"role": Role.AUDITOR}).status_code == 200
    # admin_b (objeto en memoria de la petición concurrente) intenta ahora degradar o desactivar a A
    with pytest.raises(admin_users.LastAdminError):
        admin_users.change_role(admin_b, admin_a, Role.AUDITOR)
    with pytest.raises(admin_users.LastAdminError):
        admin_users.deactivate(admin_b, admin_a)

    admin_a.refresh_from_db()
    assert admin_a.role == Role.ADMIN and admin_a.status == Status.ACTIVE
    # Y el último Administrador tampoco puede hacerlo sobre sí mismo
    assert admin_a_client.patch(f"/admin/users/{admin_a.id}/role", {"role": Role.AUDITOR}).status_code == 403


def test_us4_5_admin_creates_privileged_user_activates_via_mailbox(login_as, api_factory):
    """Escenario 5: Administrador crea cuenta privilegiada, recibe enlace en el buzón y la activa."""
    admin_client, admin = login_as("admin")
    email = "nuevo-auditor-us4@lab.securefin.local"
    resp = admin_client.post("/admin/users", {"email": email, "name": "Auditor US4", "role": Role.AUDITOR})
    assert resp.status_code == 201
    auditor = User.objects.get(id=resp.json()["id"])
    assert auditor.status == Status.PENDING_ACTIVATION and not auditor.has_usable_password()
    assert SecurityEvent.objects.filter(
        event_type="account_created_by_admin", actor_id=admin.id, target_id=auditor.id
    ).exists()

    # Correo de activación en el buzón (el token se genera al entregar y solo vive en memoria)
    assert OutboxMessage.objects.filter(user=auditor, kind="account_activation").exists()
    outbox.deliver_due()
    body = next(m.body for m in mail.outbox if m.to == [email])
    token = _TOKEN_RE.search(body).group(1)
    assert SecurityEvent.objects.filter(event_type="activation_sent", target_id=auditor.id).exists()

    newcomer = api_factory()
    assert newcomer.login(email).status_code == 401  # aún no puede entrar
    assert newcomer.post("/auth/activate", {"token": token, "password": STRONG_PASSWORD}).status_code == 204
    assert newcomer.post("/auth/activate", {"token": token, "password": STRONG_PASSWORD}).status_code == 400

    auditor.refresh_from_db()
    assert auditor.status == Status.ACTIVE
    # Debe configurar MFA antes de operar
    assert newcomer.login(email).json() == {"status": "mfa_enrollment_required"}
    assert newcomer.get("/users/me/profile").status_code == 401


def test_us4_6_mfa_reset_flow_with_admin_totp_and_email_challenge(login_as, make_user, api):
    """Escenario 6: Flujo completo de reinicio de MFA con verificación fuera de banda y TOTP del Admin."""
    admin_client, admin_user = login_as("admin")
    holder = make_user(role=Role.AUDITOR)
    holder.totp_secret = make_totp_device(holder)
    recovery_codes.generate_batch(holder)
    holder_client, _ = login_as("auditor", user=holder)  # sesión previa que debe revocarse

    # 1. Solicitud en pre_auth (contraseña verificada)
    assert api.login(holder.email).json() == {"status": "mfa_required"}
    assert api.post("/auth/login/mfa-reset-request", {}).status_code == 202
    case = MfaResetCase.objects.get(target_user=holder)
    assert case.request_verification == "password" and case.requested_by_id == holder.id

    # 2. El Administrador lo ve en su bandeja y lo abre indicando el canal fuera de banda
    listing = admin_client.get("/admin/mfa-resets?status=requested").json()["results"]
    assert any(item["case_id"] == str(case.id) for item in listing)
    open_resp = admin_client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "course_channel"})
    assert open_resp.status_code == 200

    # 3. El titular recibe el código en el buzón y se lo lee al Administrador
    code = deliver_challenge_code(holder)

    # 4. Autorización con el TOTP actual del Administrador
    auth_resp = admin_client.post(
        f"/admin/mfa-resets/{case.id}/authorize",
        {"verification_code": code, "admin_totp_code": fresh_totp(admin_user), "channel_confirmed": True},
    )
    assert auth_resp.status_code == 200 and auth_resp.json() == {"status": "authorized"}

    # Efectos: TOTP y códigos invalidados, sesiones revocadas
    assert not TOTPDevice.objects.filter(user=holder).exists()
    assert not RecoveryCode.objects.filter(user=holder, status=RecoveryCodeStatus.AVAILABLE).exists()
    assert not UserSession.objects.filter(user=holder).exists()
    assert holder_client.get("/auth/session").status_code == 401

    # Registro: solicitante, autorizador, método y fechas
    case.refresh_from_db()
    assert case.status == MfaResetStatus.AUTHORIZED
    assert case.authorized_by_id == admin_user.id and case.authorized_at is not None
    assert case.verification_method == "password+email_challenge+out_of_band:course_channel"
    event = SecurityEvent.objects.get(event_type="mfa_reset_authorized", target_id=holder.id)
    assert event.actor_id == admin_user.id
    assert set(event.metadata) == {"verification_method", "requested_at", "opened_at"}
    for kind in ("mfa_reset_requested", "mfa_reset_case_opened"):
        assert SecurityEvent.objects.filter(event_type=kind, target_id=holder.id).exists()

    # Notificación en el buzón, sin datos del Administrador
    outbox.deliver_due()
    notice = next(m for m in mail.outbox if m.to == [holder.email] and "Aviso" in m.subject)
    assert admin_user.email not in notice.body and admin_user.name not in notice.body
    assert "http" not in notice.body

    # El rol exige MFA: debe configurarlo de nuevo
    assert api.login(holder.email).json() == {"status": "mfa_enrollment_required"}


def test_us4_7_reset_does_not_reveal_or_change_password_and_user_still_needs_password(login_as, make_user, api):
    """Escenario 7: El reinicio no cambia la contraseña, no concede acceso y no muestra secretos."""
    admin_client, admin_user = login_as("admin")
    target_user = make_user(role=Role.CLIENT, password=STRONG_PASSWORD)
    old_hash = target_user.password
    case = requested_case(target_user)
    admin_client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    code = deliver_challenge_code(target_user)

    resp = admin_client.post(
        f"/admin/mfa-resets/{case.id}/authorize",
        {"verification_code": code, "admin_totp_code": fresh_totp(admin_user), "channel_confirmed": True},
    )
    assert resp.status_code == 200
    assert set(resp.json()) == {"status"}  # ni secreto ni códigos

    target_user.refresh_from_db()
    assert target_user.password == old_hash
    assert not UserSession.objects.filter(user=target_user).exists()  # no se concede sesión
    assert api.login(target_user.email, "contraseña equivocada 2026").status_code == 401
    assert api.login(target_user.email).status_code == 200  # sigue necesitando su contraseña


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
