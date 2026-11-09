"""Pruebas de integración para los servicios de US4: admin_users, activation y mfa_reset."""

from __future__ import annotations

from datetime import timedelta
import uuid
import pytest
from django.core import mail
from django.core.exceptions import ValidationError

from apps.audit.models import SecurityEvent
from apps.core import clock
from apps.iam.models import (
    MfaResetCase,
    MfaResetStatus,
    OutboxKind,
    OutboxMessage,
    RecoveryCode,
    RecoveryCodeStatus,
    Role,
    Status,
    TOTPDevice,
    User,
)
from apps.iam.services import (
    activation,
    admin_users,
    mfa_reset,
    outbox,
    recovery_codes,
    tokens,
)
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.integration


# --- admin_users.py ---------------------------------------------------------------------------------

def test_create_privileged_user_enqueues_outbox_and_audits(make_user):
    admin = make_user(role=Role.ADMIN)
    new_user = admin_users.create_privileged_user(
        admin,
        email="auditor-service@lab.securefin.local",
        name="Auditor Servicio",
        role=Role.AUDITOR,
    )
    assert new_user.status == Status.PENDING_ACTIVATION
    assert new_user.role == Role.AUDITOR
    assert not new_user.has_usable_password()

    # Outbox encolado
    assert OutboxMessage.objects.filter(
        user=new_user,
        kind=OutboxKind.ACCOUNT_ACTIVATION,
    ).exists()

    # Evento de auditoría
    assert SecurityEvent.objects.filter(
        event_type="account_created_by_admin",
        actor_id=admin.id,
        target_id=new_user.id,
    ).exists()


def test_create_privileged_user_rejects_client_role(make_user):
    admin = make_user(role=Role.ADMIN)
    with pytest.raises(admin_users.InvalidRoleError):
        admin_users.create_privileged_user(
            admin,
            email="client-rejected@lab.securefin.local",
            name="Cliente Rechazado",
            role=Role.CLIENT,
        )


def test_change_role_self_forbidden(make_user):
    admin = make_user(role=Role.ADMIN)
    with pytest.raises(admin_users.SelfOperationError):
        admin_users.change_role(admin, admin, Role.CLIENT)


def test_deactivate_self_forbidden(make_user):
    admin = make_user(role=Role.ADMIN)
    with pytest.raises(admin_users.SelfOperationError):
        admin_users.deactivate(admin, admin)


def test_last_active_admin_protection_on_degrade_and_deactivate(make_user):
    User.objects.filter(role=Role.ADMIN).delete()
    admin1 = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    admin2 = make_user(role=Role.ADMIN, status=Status.ACTIVE)

    # Con 2 administradores activos, admin1 puede desactivar a admin2
    admin_users.deactivate(admin1, admin2)
    assert admin2.status == Status.DEACTIVATED

    # Ahora admin1 es el único activo; otro intento de desactivarlo o degradarlo falla
    with pytest.raises(admin_users.LastAdminError):
        admin_users.deactivate(admin2, admin1)

    with pytest.raises(admin_users.LastAdminError):
        admin_users.change_role(admin2, admin1, Role.AUDITOR)


def test_reactivate_user(make_user):
    admin = make_user(role=Role.ADMIN)
    target = make_user(status=Status.DEACTIVATED)
    admin_users.reactivate(admin, target)
    target.refresh_from_db()
    assert target.status == Status.ACTIVE
    assert SecurityEvent.objects.filter(event_type="account_reactivated", target_id=target.id).exists()


# --- activation.py ----------------------------------------------------------------------------------

def test_activation_handler_composes_email_and_records_audit_on_delivery(make_user):
    user = make_user(status=Status.PENDING_ACTIVATION)
    msg = outbox.enqueue(OutboxKind.ACCOUNT_ACTIVATION, user)

    # Entregar mensaje
    stats = outbox.deliver_due()
    assert stats["sent"] == 1
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == [user.email]
    assert "https://securefin.local/activate#token=" in mail.outbox[0].body

    # Verifica registro de activation_sent tras entrega
    assert SecurityEvent.objects.filter(
        event_type="activation_sent",
        target_id=user.id,
    ).exists()


def test_activate_account_redeems_token_and_sets_password(make_user):
    user = make_user(status=Status.PENDING_ACTIVATION)
    token = tokens.issue(user, "account_activation")

    activated = activation.activate(token, STRONG_PASSWORD)
    assert activated.status == Status.ACTIVE
    assert activated.check_password(STRONG_PASSWORD)

    # Segundo uso falla
    with pytest.raises(tokens.InvalidToken):
        activation.activate(token, STRONG_PASSWORD)

    assert SecurityEvent.objects.filter(
        event_type="account_activated",
        actor_id=user.id,
    ).exists()


# --- mfa_reset.py -----------------------------------------------------------------------------------

def test_mfa_reset_request_idempotent_and_rate_limited(make_user, clock):
    user = make_user(role=Role.CLIENT)
    make_totp_device(user)

    # 1. Primera solicitud
    case1 = mfa_reset.request_reset(user)
    assert case1.status == MfaResetStatus.REQUESTED

    # 2. Solicitud idempotente (ya hay caso abierto)
    case2 = mfa_reset.request_reset(user)
    assert case1.id == case2.id

    # Cerrar caso1 para permitir nueva solicitud
    case1.status = MfaResetStatus.CANCELLED
    case1.save()

    case3 = mfa_reset.request_reset(user)
    case3.status = MfaResetStatus.CANCELLED
    case3.save()

    case4 = mfa_reset.request_reset(user)
    case4.status = MfaResetStatus.CANCELLED
    case4.save()

    # 4.ª solicitud en 24h excede el límite
    with pytest.raises(mfa_reset.RateLimitError):
        mfa_reset.request_reset(user)

    # Al pasar 25 horas se permite de nuevo
    clock.advance(hours=25)
    case5 = mfa_reset.request_reset(user)
    assert case5.status == MfaResetStatus.REQUESTED


def test_mfa_reset_open_case_requires_mfa_on_admin(make_user):
    admin_no_mfa = make_user(role=Role.ADMIN)
    target = make_user()
    case = mfa_reset.request_reset(target)

    with pytest.raises(mfa_reset.MfaNotEnabledError):
        mfa_reset.open_case(admin_no_mfa, case.id, "in_person")


def test_mfa_reset_full_flow(make_user, clock):
    admin = make_user(role=Role.ADMIN)
    admin_secret = make_totp_device(admin)

    target = make_user(role=Role.CLIENT)
    target_totp_secret = make_totp_device(target)
    recovery_codes.generate_batch(target)

    # 1. Titular solicita
    case = mfa_reset.request_reset(target)

    # 2. Admin abre el caso
    opened_case = mfa_reset.open_case(admin, case.id, "in_person")
    assert opened_case.status == MfaResetStatus.PENDING_VERIFICATION

    # 3. Deliver outbox envía el desafío
    assert outbox.deliver_due()["sent"] == 1
    assert len(mail.outbox) == 1
    challenge_email = mail.outbox[0].body
    import re
    match = re.search(r"([0-9A-Z]{8})", challenge_email)
    assert match is not None
    challenge_code = match.group(1)

    # 4. Autorizar con TOTP del admin y código de desafío
    authorized_case = mfa_reset.authorize(
        admin,
        case.id,
        verification_code=challenge_code,
        admin_totp_code=totp_code(admin_secret),
    )
    assert authorized_case.status == MfaResetStatus.AUTHORIZED
    assert authorized_case.challenge_verifier is None

    # Invariantes de seguridad tras autorizar:
    # TOTPDevice del titular eliminado
    assert not TOTPDevice.objects.filter(user=target).exists()
    # RecoveryCode invalidados
    assert not RecoveryCode.objects.filter(user=target, status=RecoveryCodeStatus.AVAILABLE).exists()

    # Evento de auditoría mfa_reset_authorized
    assert SecurityEvent.objects.filter(
        event_type="mfa_reset_authorized",
        actor_id=admin.id,
        target_id=target.id,
    ).exists()

    # Mensaje de aviso en outbox
    assert OutboxMessage.objects.filter(user=target, kind=OutboxKind.MFA_RESET_NOTICE).exists()


def test_mfa_reset_third_failure_cancels_case(make_user):
    admin = make_user(role=Role.ADMIN)
    admin_secret = make_totp_device(admin)
    target = make_user(role=Role.CLIENT)
    make_totp_device(target)

    case = mfa_reset.request_reset(target)
    mfa_reset.open_case(admin, case.id, "in_person")
    outbox.deliver_due()

    for i in range(2):
        with pytest.raises(mfa_reset.VerificationFailedError):
            mfa_reset.authorize(
                admin,
                case.id,
                verification_code="BADCODE1",
                admin_totp_code=totp_code(admin_secret),
            )
        case.refresh_from_db()
        assert case.status == MfaResetStatus.PENDING_VERIFICATION
        assert case.challenge_attempts == i + 1

    # 3.er fallo: pasa a cancelled
    with pytest.raises(mfa_reset.VerificationFailedError):
        mfa_reset.authorize(
            admin,
            case.id,
            verification_code="BADCODE1",
            admin_totp_code=totp_code(admin_secret),
        )

    case.refresh_from_db()
    assert case.status == MfaResetStatus.CANCELLED
    assert case.challenge_verifier is None

    # 4.º intento da CaseConflictError
    with pytest.raises(mfa_reset.CaseConflictError):
        mfa_reset.authorize(
            admin,
            case.id,
            verification_code="BADCODE1",
            admin_totp_code=totp_code(admin_secret),
        )

