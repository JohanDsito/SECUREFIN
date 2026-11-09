"""Reinicio administrativo de MFA (T089; R11; FR-032 a FR-035).

Procedimiento verificable en varias etapas:
1. `request_reset`: El titular solicita desde pre_auth (contraseña verificada). Cierra la sesión pre_auth.
   Máximo 3 solicitudes por titular en 24 h. Idempotente si ya existe un caso abierto.
2. `open_case`: El Administrador con MFA activo (distinto del titular) verifica identidad fuera de banda,
   selecciona el canal y abre el caso (estado pending_verification). Encola mfa_reset_challenge en el outbox.
3. Handler `mfa_reset_challenge`: genera código de 8 caracteres en base32 Crockford (10 min de expiración)
   y lo entrega por correo sin enlaces. Se persiste solo su hash Argon2id.
4. `authorize`: El Administrador que abrió el caso confirma el código de verificación y su propio código TOTP actual.
   Máximo 3 intentos de verificación (al 3.º fallo el caso pasa a 'cancelled').
   Al autorizar: invalida TOTPDevice y RecoveryCode del titular, revoca sus sesiones con `session_admin.revoke_all`,
   borra `challenge_verifier`, guarda `verification_method = "password+email_challenge+out_of_band:<canal>"`,
   registra 'mfa_reset_authorized' y encola 'mfa_reset_notice'.
5. `cancel`: Cancela el caso, borra el verificador del desafío y registra 'mfa_reset_cancelled'.
"""

from __future__ import annotations

from datetime import timedelta
import uuid

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from django.db import transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.crypto import codes
from apps.iam.models import (
    MfaResetCase,
    MfaResetStatus,
    OutboxKind,
    OutboxMessage,
    RecoveryCode,
    RecoveryCodeStatus,
    RequestChannel,
    RequestVerification,
    TOTPDevice,
    User,
)
from apps.iam.services import outbox, session_admin
from apps.iam.services.mfa_state import user_mfa_enabled

_challenge_hasher = PasswordHasher(
    memory_cost=19456, time_cost=2, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)


class MfaResetError(Exception):
    """Error base en reinicio de MFA."""


class RateLimitError(MfaResetError):
    """Límite de 3 solicitudes en 24 horas excedido."""


class SelfOperationError(MfaResetError):
    """Un Administrador no puede operar sobre su propio reinicio."""


class WrongAdminError(MfaResetError):
    """Solo el Administrador que abrió el caso puede autorizarlo."""


class CaseConflictError(MfaResetError):
    """El caso no está en el estado requerido o ha caducado."""


class VerificationFailedError(MfaResetError):
    """Código de verificación o TOTP del Administrador inválido."""


class MfaNotEnabledError(MfaResetError):
    """El Administrador debe tener MFA activo para gestionar casos."""


def request_reset(user: User, source_ip: str | None = None) -> MfaResetCase:
    """Registra la solicitud de reinicio de MFA de un titular en sesión pre_auth."""
    now = clock.now()
    window_start = now - timedelta(hours=24)

    recent_count = MfaResetCase.objects.filter(
        target_user=user,
        requested_at__gte=window_start,
    ).count()
    if recent_count >= 3:
        raise RateLimitError("Límite de solicitudes de reinicio excedido en las últimas 24 horas.")

    # Idempotencia si ya existe un caso abierto
    existing = MfaResetCase.objects.filter(
        target_user=user,
        status__in=[MfaResetStatus.REQUESTED, MfaResetStatus.PENDING_VERIFICATION],
    ).first()
    if existing:
        session_admin.revoke_all(user, actor=user, reason="mfa_reset_requested")
        return existing

    with transaction.atomic():
        case = MfaResetCase.objects.create(
            target_user=user,
            requested_by=user,
            request_verification=RequestVerification.PASSWORD,
            status=MfaResetStatus.REQUESTED,
            requested_at=now,
        )
        record_event(
            "mfa_reset_requested",
            "success",
            actor=user,
            target_type="user",
            target_id=user.id,
            source_ip=source_ip,
        )
        session_admin.revoke_all(user, actor=user, reason="mfa_reset_requested")

    return case


def open_case(
    admin_user: User,
    case_id: uuid.UUID | str,
    request_channel: str,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Abre un caso solicitado, valida MFA del admin y encola el desafío."""
    if not user_mfa_enabled(admin_user):
        raise MfaNotEnabledError("El Administrador debe contar con MFA activo.")

    if request_channel not in RequestChannel.values:
        raise ValueError(f"Canal no permitido: {request_channel}")

    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().get(id=case_id)

        if case.target_user_id == admin_user.id:
            raise SelfOperationError("Un Administrador no puede abrir un caso de reinicio para sí mismo.")

        if case.status != MfaResetStatus.REQUESTED:
            raise CaseConflictError(f"El caso no se encuentra en estado requested (actual: {case.status}).")

        case.opened_by = admin_user
        case.request_channel = request_channel
        case.opened_at = clock.now()
        case.status = MfaResetStatus.PENDING_VERIFICATION
        case.save(update_fields=["opened_by", "request_channel", "opened_at", "status"])

        outbox.enqueue(OutboxKind.MFA_RESET_CHALLENGE, case.target_user, related_id=case.id)
        record_event(
            "mfa_reset_case_opened",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=case.target_user_id,
            source_ip=source_ip,
            metadata={"channel": request_channel},
        )

    return case


def handle_mfa_reset_challenge(message: OutboxMessage) -> outbox.ComposedEmail:
    """Handler del outbox: genera código de desafío de 8 caracteres y lo guarda hasheado en el caso."""
    code = codes.generate_verification_code()
    now = clock.now()

    case = MfaResetCase.objects.get(id=message.related_id)
    case.challenge_verifier = _challenge_hasher.hash(code)
    case.challenge_expires_at = now + timedelta(minutes=10)
    case.save(update_fields=["challenge_verifier", "challenge_expires_at"])

    channel_name = case.get_request_channel_display()
    body = (
        f"Hola {message.user.name},\n\n"
        f"Se ha iniciado un proceso de reinicio de tu segundo factor de autenticación (MFA).\n"
        f"Tu código de verificación de 8 caracteres es:\n\n"
        f"    {code}\n\n"
        f"Por seguridad, lee este código ÚNICAMENTE al Administrador por el canal acordado ({channel_name}).\n"
        f"Este código caduca en 10 minutos.\n"
    )
    return outbox.ComposedEmail(
        subject="Código de verificación para reinicio de MFA",
        body=body,
    )


outbox.register_handler(OutboxKind.MFA_RESET_CHALLENGE, handle_mfa_reset_challenge)


def handle_mfa_reset_notice(message: OutboxMessage) -> outbox.ComposedEmail:
    """Handler del outbox: aviso sin secretos ni tokens informando del reinicio del segundo factor."""
    body = (
        f"Hola {message.user.name},\n\n"
        f"Te informamos que tu segundo factor de autenticación (MFA) ha sido reiniciado "
        f"por el equipo de administración el {clock.now().strftime('%Y-%m-%d %H:%M:%S UTC')}.\n\n"
        f"Tus dispositivos TOTP y códigos de recuperación anteriores han quedado invalidados.\n"
        f"Si tú no solicitaste este cambio, por favor contacta de inmediato con el soporte de seguridad.\n"
    )
    return outbox.ComposedEmail(
        subject="Aviso de reinicio de tu segundo factor (MFA)",
        body=body,
    )


outbox.register_handler(OutboxKind.MFA_RESET_NOTICE, handle_mfa_reset_notice)


class _VerificationFailure(Exception):
    """Fallo interno para provocar rollback del proceso de éxito y persistir el fallo."""


def authorize(
    admin_user: User,
    case_id: uuid.UUID | str,
    verification_code: str,
    admin_totp_code: str,
    channel_confirmed: bool = True,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Valida el código de desafío y el TOTP del Administrador, invalidando el MFA del titular."""
    from apps.iam.services import mfa

    # Verificar estado y vigencia preliminar
    case_obj = MfaResetCase.objects.get(id=case_id)
    if case_obj.opened_by_id != admin_user.id:
        raise WrongAdminError("Solo el Administrador que abrió el caso puede autorizarlo.")
    if case_obj.status != MfaResetStatus.PENDING_VERIFICATION:
        raise CaseConflictError(f"El caso no está pendiente de verificación (estado actual: {case_obj.status}).")
    if case_obj.is_challenge_expired():
        with transaction.atomic():
            case = MfaResetCase.objects.select_for_update().get(id=case_id)
            case.status = MfaResetStatus.EXPIRED
            case.clear_challenge()
            case.save(update_fields=["status", "challenge_verifier", "challenge_expires_at"])
        raise CaseConflictError("El código de verificación ha caducado.")
    if case_obj.challenge_attempts >= 3:
        with transaction.atomic():
            case = MfaResetCase.objects.select_for_update().get(id=case_id)
            case.status = MfaResetStatus.CANCELLED
            case.clear_challenge()
            case.save(update_fields=["status", "challenge_verifier", "challenge_expires_at"])
        raise CaseConflictError("Se ha superado el máximo de intentos permitidos.")

    try:
        with transaction.atomic():
            case = MfaResetCase.objects.select_for_update().get(id=case_id)

            if case.opened_by_id != admin_user.id:
                raise WrongAdminError("Solo el Administrador que abrió el caso puede autorizarlo.")
            if case.status != MfaResetStatus.PENDING_VERIFICATION:
                raise CaseConflictError(f"El caso no está pendiente de verificación (estado actual: {case.status}).")
            if case.is_challenge_expired():
                raise CaseConflictError("El código de verificación ha caducado.")
            if case.challenge_attempts >= 3:
                raise CaseConflictError("Se ha superado el máximo de intentos permitidos.")

            # 1. Verificar TOTP del administrador actual
            if not mfa.verify_totp(admin_user, admin_totp_code):
                raise _VerificationFailure

            # 2. Verificar código de desafío
            normalized_code = codes.normalize_code(verification_code)
            if not normalized_code or not case.challenge_verifier:
                raise _VerificationFailure

            try:
                if not _challenge_hasher.verify(case.challenge_verifier, normalized_code):
                    raise _VerificationFailure
            except (VerificationError, InvalidHashError):
                raise _VerificationFailure

            # Éxito en la verificación:
            target_user = case.target_user

            # Invalidar dispositivo TOTP
            TOTPDevice.objects.filter(user=target_user).delete()

            # Invalidar lote de códigos de recuperación
            RecoveryCode.objects.filter(user=target_user).update(status=RecoveryCodeStatus.INVALIDATED)

            # Revocar sesiones del titular
            session_admin.revoke_all(target_user, actor=admin_user, reason="mfa_reset")

            # Limpiar verificador del desafío y actualizar caso
            case.clear_challenge()
            case.status = MfaResetStatus.AUTHORIZED
            case.authorized_by = admin_user
            case.authorized_at = clock.now()
            case.verification_method = f"password+email_challenge+out_of_band:{case.request_channel}"
            case.save(
                update_fields=[
                    "status",
                    "challenge_verifier",
                    "challenge_expires_at",
                    "authorized_by",
                    "authorized_at",
                    "verification_method",
                ]
            )

            record_event(
                "mfa_reset_authorized",
                "success",
                actor=admin_user,
                target_type="user",
                target_id=target_user.id,
                source_ip=source_ip,
                metadata={
                    "verification_method": case.verification_method,
                    "requested_at": case.requested_at.isoformat(),
                    "opened_at": case.opened_at.isoformat() if case.opened_at else "",
                },
            )

            outbox.enqueue(OutboxKind.MFA_RESET_NOTICE, target_user)
            return case

    except _VerificationFailure:
        with transaction.atomic():
            case = MfaResetCase.objects.select_for_update().get(id=case_id)
            case.challenge_attempts += 1
            if case.challenge_attempts >= 3:
                case.status = MfaResetStatus.CANCELLED
                case.clear_challenge()
            case.save(
                update_fields=[
                    "challenge_attempts",
                    "status",
                    "challenge_verifier",
                    "challenge_expires_at",
                ]
            )
        raise VerificationFailedError("Código de verificación o TOTP inválido.")


def cancel(
    admin_user: User,
    case_id: uuid.UUID | str,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Cancela un caso de reinicio de MFA y borra el verificador del desafío."""
    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().get(id=case_id)
        case.status = MfaResetStatus.CANCELLED
        case.clear_challenge()
        case.save(update_fields=["status", "challenge_verifier", "challenge_expires_at"])

        record_event(
            "mfa_reset_cancelled",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=case.target_user_id,
            source_ip=source_ip,
        )

    return case
