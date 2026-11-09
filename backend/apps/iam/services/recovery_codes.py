"""Códigos de recuperación de MFA (T075; R6; FR-028 a FR-030).

- 10 códigos por lote, 28 caracteres de base32 de Crockford (140 bits) generados con `secrets`.
- Solo se guarda un verificador Argon2id (m=19 MiB, t=2, p=1) por código; el código en claro se
  devuelve una única vez.
- Uso único: verificación y marcado como `used` en la misma transacción con `select_for_update`,
  de modo que dos peticiones concurrentes no consumen el mismo código.
- Generar un lote invalida el anterior.
"""

from __future__ import annotations

import uuid

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from django.db import transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.crypto import codes
from apps.iam.models import RecoveryCode, RecoveryCodeStatus
from apps.iam.services.mfa_state import lock_user_mfa

BATCH_SIZE = 10

_hasher = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)


def _invalidate_available(user) -> None:
    RecoveryCode.objects.filter(user=user, status=RecoveryCodeStatus.AVAILABLE).update(
        status=RecoveryCodeStatus.INVALIDATED
    )


def generate_batch(user) -> list[str]:
    """Crea un lote nuevo (invalida el anterior) y devuelve los códigos en claro, sin guiones."""
    batch_id = uuid.uuid4()
    raw_codes = [codes.generate_recovery_code() for _ in range(BATCH_SIZE)]
    # Los hashes (costosos) se calculan antes de tomar el bloqueo del usuario.
    rows = [RecoveryCode(user=user, batch_id=batch_id, verifier=_hasher.hash(raw)) for raw in raw_codes]
    with transaction.atomic():
        lock_user_mfa(user)
        _invalidate_available(user)
        RecoveryCode.objects.bulk_create(rows)
    return raw_codes


def invalidate_all(user) -> None:
    with transaction.atomic():
        _invalidate_available(user)


def consume(user, raw: str | None) -> int | None:
    """Consume un código. Devuelve los códigos restantes, o None si no es válido o ya se usó."""
    normalized = codes.normalize_code(raw) if isinstance(raw, str) else None
    if not normalized or len(normalized) != codes.RECOVERY_CODE_LENGTH:
        return None
    with transaction.atomic():
        available = list(
            RecoveryCode.objects.select_for_update()
            .filter(user=user, status=RecoveryCodeStatus.AVAILABLE)
            .order_by("id")
        )
        match = None
        for candidate in available:
            try:
                if _hasher.verify(candidate.verifier, normalized):
                    match = candidate
                    break
            except (VerificationError, InvalidHashError):
                continue
        if match is None:
            return None
        match.status = RecoveryCodeStatus.USED
        match.used_at = clock.now()
        match.save(update_fields=["status", "used_at"])
        remaining = len(available) - 1
        record_event(
            "recovery_code_used",
            "success",
            actor=user,
            target_type="user",
            target_id=user.id,
            metadata={"remaining": remaining},
        )
    return remaining


def regenerate(user, password: str, totp: str, session=None) -> list[str]:
    """Nuevo lote tras confirmar contraseña y TOTP (FR-030); revoca las demás sesiones (FR-012)."""
    from apps.iam.services import mfa, session_admin

    mfa.require_active(user)
    mfa.reauthenticate(user, password, totp)
    with transaction.atomic():
        new_codes = generate_batch(user)
        record_event("recovery_codes_regenerated", "success", actor=user, target_type="user", target_id=user.id)
    session_admin.rotate_after_mfa_change(user, session)
    return new_codes
