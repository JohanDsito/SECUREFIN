"""Segundo factor: dispositivo TOTP cifrado y códigos de recuperación (T073; data-model; R5, R6).

Desviación documentada del data-model: `TOTPDevice.user` es una FK en lugar de OneToOne. Así un
usuario puede tener a la vez su dispositivo `active` y un alta `pending` de reconfiguración: el activo
solo se sustituye al confirmar el nuevo, y abandonar la reconfiguración no deja la cuenta sin MFA.

La invariante "como máximo un `active` y un `pending` por usuario" se impone con dos restricciones
únicas **condicionales** (índices únicos parciales en PostgreSQL), no con `unique(user, status)`: la
unicidad solo afecta a los estados abiertos y un futuro estado histórico (p. ej. `revoked`) podría
acumular filas sin cambiar las restricciones. El servicio serializa además las operaciones de MFA de
cada usuario bloqueando su fila (services.mfa).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models

from apps.core import clock

PENDING_ENROLLMENT_TTL = timedelta(minutes=10)


class TOTPStatus(models.TextChoices):
    PENDING = "pending", "Alta pendiente de confirmar"
    ACTIVE = "active", "Activo"


class TOTPDevice(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_devices")
    status = models.CharField(max_length=10, choices=TOTPStatus.choices)
    # AES-256-GCM con etiqueta; AAD = "securefin:totp:v1:" + user.id. Nunca el secreto en claro.
    secret_ciphertext = models.BinaryField()
    nonce = models.BinaryField(max_length=12)
    key_version = models.CharField(max_length=6)
    last_used_timestep = models.BigIntegerField(null=True)  # antirrepetición (estrictamente creciente)
    created_at = models.DateTimeField(default=clock.default_now)
    confirmed_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "iam_totpdevice"
        constraints = [
            models.UniqueConstraint(
                fields=["user"], condition=models.Q(status="active"), name="iam_totp_one_active_per_user"
            ),
            models.UniqueConstraint(
                fields=["user"], condition=models.Q(status="pending"), name="iam_totp_one_pending_per_user"
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=[TOTPStatus.PENDING, TOTPStatus.ACTIVE]),
                name="iam_totp_status_valid",
            ),
        ]

    def is_expired_pending(self) -> bool:
        return self.status == TOTPStatus.PENDING and clock.now() >= self.created_at + PENDING_ENROLLMENT_TTL

    def __str__(self) -> str:  # nunca expone el secreto
        return f"TOTPDevice({self.id}, {self.status})"


class RecoveryCodeStatus(models.TextChoices):
    AVAILABLE = "available", "Disponible"
    USED = "used", "Usado"
    INVALIDATED = "invalidated", "Invalidado"


class RecoveryCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recovery_codes")
    batch_id = models.UUIDField()
    verifier = models.CharField(max_length=128)  # Argon2id (m=19 MiB, t=2, p=1); nunca el código
    status = models.CharField(
        max_length=12, choices=RecoveryCodeStatus.choices, default=RecoveryCodeStatus.AVAILABLE
    )
    created_at = models.DateTimeField(default=clock.default_now)
    used_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "iam_recoverycode"
        indexes = [models.Index(fields=["user", "status"], name="iam_recovery_user_status_idx")]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(status__in=["available", "used", "invalidated"]),
                name="iam_recovery_status_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"RecoveryCode({self.id}, {self.status})"
