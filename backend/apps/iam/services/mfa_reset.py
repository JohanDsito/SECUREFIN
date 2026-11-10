"""Reinicio administrativo de MFA (T089; R11; FR-032 a FR-035).

Procedimiento verificable en varias etapas:
1. `request_reset`: el titular solicita desde pre_auth (contraseña verificada) y con MFA activo. Se
   cierra la sesión pre_auth. Idempotente si ya hay un caso abierto; como máximo 3 casos por
   titular cada 24 h.
2. `open_case`: un Administrador con MFA activo (distinto del titular) verifica la identidad fuera de
   banda, registra el canal y abre el caso (`pending_verification`). Encola `mfa_reset_challenge`.
3. Handler `mfa_reset_challenge`: genera un código de 8 caracteres (base32 de Crockford), guarda solo
   su verificador Argon2id y lo envía sin enlaces; caduca 10 min después de la entrega.
4. `authorize`: el Administrador que abrió el caso confirma el código y su propio TOTP actual. Como
   máximo 3 intentos: al tercer fallo el caso pasa a `cancelled` (con evento). Al autorizar, en una
   única transacción: invalida el TOTP y los códigos de recuperación del titular, revoca sus
   sesiones, borra `challenge_verifier`, guarda `verification_method`, registra
   `mfa_reset_authorized` y encola `mfa_reset_notice`.
5. `cancel`: cancela un caso abierto, borra el verificador y registra `mfa_reset_cancelled`.

Caducidad (data-model): `requested` → `expired` a las 24 h sin abrir; `pending_verification` →
`expired` a los 10 min de la entrega del código. Se aplica de forma perezosa (`_expire_stale`) antes
de cualquier lectura o transición, de modo que un caso caducado nunca bloquea una solicitud nueva.

Garantías: nunca modifica la contraseña, nunca concede una sesión y nunca devuelve secretos.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from django.db import IntegrityError, transaction
from django.db.models import Q

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
    Status,
    TOTPDevice,
    User,
)
from apps.iam.models.mfa_reset import (
    CHALLENGE_TTL,
    MAX_CHALLENGE_ATTEMPTS,
    MAX_REQUESTS_PER_WINDOW,
    REQUEST_WINDOW,
)
from apps.iam.services import outbox, session_admin
from apps.iam.services.mfa_state import lock_user_mfa, user_mfa_enabled

_challenge_hasher = PasswordHasher(
    memory_cost=19456, time_cost=2, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)

OPEN_STATUSES = (MfaResetStatus.REQUESTED, MfaResetStatus.PENDING_VERIFICATION)


class MfaResetError(Exception):
    """Error base en reinicio de MFA."""


class RateLimitError(MfaResetError):
    """Límite de 3 solicitudes en 24 horas excedido."""

    def __init__(self, retry_after: int):
        super().__init__("Límite de solicitudes de reinicio excedido.")
        self.retry_after = retry_after


class SelfOperationError(MfaResetError):
    """Un Administrador no puede operar sobre su propio reinicio."""


class WrongAdminError(MfaResetError):
    """Solo el Administrador que abrió el caso puede autorizarlo."""


class CaseConflictError(MfaResetError):
    """El caso no está en el estado requerido o ha caducado."""


class CaseNotFoundError(MfaResetError):
    """No existe el caso (o el identificador está mal formado)."""


class VerificationFailedError(MfaResetError):
    """Código de verificación o TOTP del Administrador inválido."""


class MfaNotEnabledError(MfaResetError):
    """El usuario (Administrador o titular) no tiene MFA activo."""


# --- Utilidades -------------------------------------------------------------------------------------
def _case_pk(case_id) -> uuid.UUID:
    try:
        return uuid.UUID(str(case_id))
    except ValueError as exc:
        raise CaseNotFoundError from exc


def _expire_stale(now: datetime | None = None, **filters) -> int:
    """Marca como `expired` los casos abiertos caducados y borra su verificador."""
    now = now or clock.now()
    stale = Q(status=MfaResetStatus.REQUESTED, requested_at__lte=now - REQUEST_WINDOW) | Q(
        status=MfaResetStatus.PENDING_VERIFICATION, challenge_expires_at__lte=now
    )
    return MfaResetCase.objects.filter(stale, **filters).update(
        status=MfaResetStatus.EXPIRED, challenge_verifier=None, challenge_expires_at=None
    )


def _challenge_matches(case: MfaResetCase, raw_code) -> bool:
    normalized = codes.normalize_code(raw_code) if isinstance(raw_code, str) else None
    if not normalized or not case.challenge_verifier:
        return False
    try:
        return _challenge_hasher.verify(case.challenge_verifier, normalized)
    except (VerificationError, InvalidHashError):
        return False


@dataclass(frozen=True)
class CaseSummary:
    case_id: uuid.UUID
    target_user_id: uuid.UUID
    target_email: str
    requested_at: datetime
    status: str


# --- Consultas --------------------------------------------------------------------------------------
def list_cases(status: str | None = None) -> list[CaseSummary]:
    """Casos para la bandeja del Administrador (contrato §4). Nunca incluye verificadores."""
    _expire_stale()
    qs = MfaResetCase.objects.select_related("target_user").order_by("requested_at")
    if status:
        qs = qs.filter(status=status)
    return [
        CaseSummary(c.id, c.target_user_id, c.target_user.email, c.requested_at, c.status) for c in qs
    ]


# --- 1. Solicitud del titular -----------------------------------------------------------------------
def request_reset(user: User, source_ip: str | None = None) -> MfaResetCase:
    """Registra la solicitud de reinicio del titular (pre_auth) y revoca todas sus sesiones."""
    now = clock.now()
    with transaction.atomic():
        lock_user_mfa(user)  # serializa solicitudes simultáneas del mismo titular
        if not user_mfa_enabled(user):
            raise MfaNotEnabledError("El titular no tiene MFA activo.")
        _expire_stale(now, target_user=user)

        existing = MfaResetCase.objects.filter(target_user=user, status__in=OPEN_STATUSES).first()
        if existing is not None:  # idempotente: misma respuesta, sin caso nuevo
            session_admin.revoke_all(user, actor=user, reason="mfa_reset_requested")
            return existing

        recent = list(
            MfaResetCase.objects.filter(target_user=user, requested_at__gt=now - REQUEST_WINDOW)
            .order_by("requested_at")
            .values_list("requested_at", flat=True)
        )
        if len(recent) >= MAX_REQUESTS_PER_WINDOW:
            retry_after = int((recent[0] + REQUEST_WINDOW - now).total_seconds()) + 1
            raise RateLimitError(max(retry_after, 1))

        try:
            with transaction.atomic():
                case = MfaResetCase.objects.create(
                    target_user=user,
                    requested_by=user,
                    request_verification=RequestVerification.PASSWORD,
                    status=MfaResetStatus.REQUESTED,
                    requested_at=now,
                )
        except IntegrityError as exc:  # otro caso abierto creado en paralelo
            raise CaseConflictError("Ya existe un caso abierto.") from exc

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


# --- 2. Apertura por el Administrador ---------------------------------------------------------------
def open_case(
    admin_user: User,
    case_id,
    request_channel: str,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Abre un caso `requested`, registra el canal fuera de banda y encola el desafío."""
    if not user_mfa_enabled(admin_user):
        raise MfaNotEnabledError("El Administrador debe contar con MFA activo.")
    if request_channel not in RequestChannel.values:
        raise ValueError("Canal no permitido.")
    pk = _case_pk(case_id)

    _expire_stale(id=pk)  # en su propia transacción: un 409 posterior no la deshace
    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().select_related("target_user").filter(pk=pk).first()
        if case is None:
            raise CaseNotFoundError
        if case.target_user_id == admin_user.id:
            raise SelfOperationError("Un Administrador no puede abrir un caso de reinicio para sí mismo.")
        if case.status != MfaResetStatus.REQUESTED:
            raise CaseConflictError("El caso no está en estado requested.")
        if case.target_user.status != Status.ACTIVE:
            raise CaseConflictError("La cuenta del titular no está activa.")

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


# --- 3. Desafío por correo (outbox) -----------------------------------------------------------------
class ChallengeNotApplicable(Exception):
    """El caso ya no espera un código (cancelado, caducado o autorizado): no se envía nada."""


def handle_mfa_reset_challenge(message: OutboxMessage) -> outbox.ComposedEmail:
    """Genera el código de 8 caracteres, guarda solo su verificador y compone el correo."""
    code = codes.generate_verification_code()
    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().filter(pk=message.related_id).first()
        if case is None or case.status != MfaResetStatus.PENDING_VERIFICATION:
            # Nunca se escribe un verificador en un caso cerrado. El outbox reintenta y acaba en
            # `failed` con `email_delivery_failed`, sin código ni cuerpo.
            raise ChallengeNotApplicable
        case.challenge_verifier = _challenge_hasher.hash(code)
        case.challenge_expires_at = clock.now() + CHALLENGE_TTL
        case.save(update_fields=["challenge_verifier", "challenge_expires_at"])
        channel_name = case.get_request_channel_display()

    body = (
        f"Hola {message.user.name},\n\n"
        "Se ha iniciado un proceso de reinicio de tu segundo factor de autenticación (MFA).\n"
        "Tu código de verificación de 8 caracteres es:\n\n"
        f"    {code}\n\n"
        f"Por seguridad, lee este código ÚNICAMENTE al Administrador por el canal acordado ({channel_name}).\n"
        "Este código caduca en 10 minutos. Si no has solicitado el reinicio, no lo compartas.\n"
    )
    return outbox.ComposedEmail(subject="Código de verificación para reinicio de MFA", body=body)


outbox.register_handler(OutboxKind.MFA_RESET_CHALLENGE, handle_mfa_reset_challenge)


def handle_mfa_reset_notice(message: OutboxMessage) -> outbox.ComposedEmail:
    """Aviso al titular (contrato §8): fecha, aviso y qué hacer; sin datos del Administrador."""
    body = (
        f"Hola {message.user.name},\n\n"
        "Te informamos de que un Administrador ha reiniciado tu segundo factor de autenticación (MFA) "
        f"el {message.created_at.strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
        "Tu dispositivo TOTP y tus códigos de recuperación anteriores ya no son válidos. Tu contraseña "
        "no ha cambiado: en tu próximo inicio de sesión tendrás que configurar de nuevo el MFA si tu "
        "rol lo exige.\n\n"
        "Si no solicitaste este reinicio, recupera tu contraseña de inmediato y contacta con el equipo "
        "de seguridad del laboratorio.\n"
    )
    return outbox.ComposedEmail(subject="Aviso de reinicio de tu segundo factor (MFA)", body=body)


outbox.register_handler(OutboxKind.MFA_RESET_NOTICE, handle_mfa_reset_notice)


# --- 4. Autorización --------------------------------------------------------------------------------
def invalidate_mfa(target: User) -> None:
    lock_user_mfa(target)
    TOTPDevice.objects.filter(user=target).delete()
    RecoveryCode.objects.filter(user=target, status=RecoveryCodeStatus.AVAILABLE).update(
        status=RecoveryCodeStatus.INVALIDATED
    )


def authorize(
    admin_user: User,
    case_id,
    verification_code: str,
    admin_totp_code: str,
    channel_confirmed: bool = True,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Valida el código del titular y el TOTP del Administrador e invalida el MFA del titular."""
    if channel_confirmed is not True:
        raise ValueError("Hay que confirmar el canal fuera de banda.")
    pk = _case_pk(case_id)
    error: MfaResetError | None = None

    _expire_stale(id=pk)  # en su propia transacción: un 409 posterior no la deshace
    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().select_related("target_user").filter(pk=pk).first()
        if case is None:
            raise CaseNotFoundError
        if case.target_user_id == admin_user.id:
            raise SelfOperationError("Un Administrador no puede autorizar su propio reinicio.")
        if case.status != MfaResetStatus.PENDING_VERIFICATION:
            raise CaseConflictError("El caso no está pendiente de verificación.")
        if case.opened_by_id != admin_user.id:
            raise WrongAdminError("Solo el Administrador que abrió el caso puede autorizarlo.")

        # Se evalúan siempre los dos factores (sin cortocircuito). El TOTP correcto se consume.
        from apps.iam.services import mfa

        totp_ok = mfa.verify_totp(admin_user, admin_totp_code)
        code_ok = _challenge_matches(case, verification_code)

        if totp_ok and code_ok:
            target = case.target_user
            invalidate_mfa(target)
            session_admin.revoke_all(target, actor=admin_user, reason="mfa_reset")

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
                target_id=target.id,  # el titular es también el solicitante (requested_by)
                source_ip=source_ip,
                metadata={
                    "verification_method": case.verification_method,
                    "requested_at": case.requested_at.isoformat(),
                    "opened_at": case.opened_at.isoformat() if case.opened_at else "",
                },
            )
            outbox.enqueue(OutboxKind.MFA_RESET_NOTICE, target, related_id=case.id)
        else:
            case.challenge_attempts += 1
            fields = ["challenge_attempts"]
            if case.challenge_attempts >= MAX_CHALLENGE_ATTEMPTS:
                case.status = MfaResetStatus.CANCELLED
                case.clear_challenge()
                fields += ["status", "challenge_verifier", "challenge_expires_at"]
                record_event(
                    "mfa_reset_cancelled",
                    "failure",
                    actor=admin_user,
                    target_type="user",
                    target_id=case.target_user_id,
                    source_ip=source_ip,
                    metadata={"reason": "max_attempts"},
                )
            case.save(update_fields=fields)
            error = VerificationFailedError("Código de verificación o TOTP inválido.")

    if error is not None:
        raise error
    return case


# --- 5. Cancelación ---------------------------------------------------------------------------------
def cancel(
    admin_user: User,
    case_id,
    source_ip: str | None = None,
) -> MfaResetCase:
    """Cancela un caso abierto y borra el verificador del desafío."""
    pk = _case_pk(case_id)
    _expire_stale(id=pk)  # en su propia transacción: un 409 posterior no la deshace
    with transaction.atomic():
        case = MfaResetCase.objects.select_for_update().filter(pk=pk).first()
        if case is None:
            raise CaseNotFoundError
        if case.target_user_id == admin_user.id:
            raise SelfOperationError("Un Administrador no puede gestionar su propio reinicio.")
        if case.status not in OPEN_STATUSES:
            raise CaseConflictError("El caso ya está resuelto.")

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
            metadata={"reason": "admin_cancelled"},
        )
    return case
