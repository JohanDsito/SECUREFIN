"""Emisión y canje de tokens de un solo uso (T042; R7; FR-021, FR-046).

- Token: ``secrets.token_urlsafe(32)`` (256 bits). Solo se devuelve en memoria a quien lo envía.
- Se guarda únicamente ``HMAC-SHA-256(TOKEN_HMAC_KEYS[v], purpose + ":" + token)``.
- Emitir uno nuevo invalida los pendientes del mismo usuario y propósito.
- El canje es transaccional (``select_for_update``) y de un solo uso.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from django.db import transaction

from apps.core import clock
from apps.iam.crypto import hmac_verifiers
from apps.iam.models import OneTimeToken, TokenPurpose

TOKEN_TTL = {
    TokenPurpose.ACCOUNT_ACTIVATION: timedelta(hours=24),
    TokenPurpose.PASSWORD_RESET: timedelta(minutes=15),  # FR-046
}


class InvalidToken(Exception):
    """Mismo error para token usado, caducado, sustituido, alterado o de otro propósito."""


def issue(user, purpose: str) -> str:
    """Emite un token nuevo y devuelve su valor en claro SOLO en memoria."""
    purpose = TokenPurpose(purpose)
    now = clock.now()
    token = secrets.token_urlsafe(32)
    version, verifier = hmac_verifiers.token_verifier(purpose, token)
    with transaction.atomic():
        OneTimeToken.objects.filter(
            user=user, purpose=purpose, used_at__isnull=True, invalidated_at__isnull=True
        ).update(invalidated_at=now)
        OneTimeToken.objects.create(
            user=user,
            purpose=purpose,
            verifier=verifier,
            key_version=version,
            created_at=now,
            expires_at=now + TOKEN_TTL[purpose],
        )
    return token


def redeem(token: str, purpose: str):
    """Canjea el token y devuelve su usuario; lanza InvalidToken ante cualquier fallo."""
    purpose = TokenPurpose(purpose)
    if not token or len(token) > 128:
        raise InvalidToken
    candidates = [v for _ver, v in hmac_verifiers.token_verifiers_accepted(purpose, token)]
    now = clock.now()
    with transaction.atomic():
        record = (
            OneTimeToken.objects.select_for_update()
            .select_related("user")
            .filter(verifier__in=candidates, purpose=purpose)
            .first()
        )
        if record is None or not any(hmac_verifiers.verify(record.verifier, c) for c in candidates):
            raise InvalidToken
        if record.used_at or record.invalidated_at or record.expires_at <= now:
            raise InvalidToken
        record.used_at = now
        record.save(update_fields=["used_at"])
        return record.user
