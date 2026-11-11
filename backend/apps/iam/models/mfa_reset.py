"""Casos de reinicio administrativo de MFA (T088; R11; data-model → MfaResetCase).

- Procedimiento de verificación de identidad fuera de banda.
- El titular solicita en pre_auth (contraseña verificada).
- Un Administrador con MFA activo (distinto del titular) abre el caso y selecciona el canal.
- Se genera un código de desafío de 8 caracteres al buzón de laboratorio (10 min de validez).
- El Administrador autoriza confirmando el código y su propio código TOTP actual.
- Al autorizar o cancelar, `challenge_verifier` se borra inmediatamente.
- Restricción: como máximo un caso abierto ('requested' o 'pending_verification') por titular.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models

from apps.core import clock

CHALLENGE_TTL = timedelta(minutes=10)
REQUEST_WINDOW = timedelta(hours=24)
MAX_CHALLENGE_ATTEMPTS = 3
MAX_REQUESTS_PER_WINDOW = 3


class RequestVerification(models.TextChoices):
    PASSWORD = "password", "Contraseña"
    CONSOLE = "console", "Consola"


class RequestChannel(models.TextChoices):
    IN_PERSON = "in_person", "En persona"
    COURSE_CHANNEL = "course_channel", "Canal de curso"


class MfaResetStatus(models.TextChoices):
    REQUESTED = "requested", "Solicitado"
    PENDING_VERIFICATION = "pending_verification", "Verificación pendiente"
    AUTHORIZED = "authorized", "Autorizado"
    CANCELLED = "cancelled", "Cancelado"
    EXPIRED = "expired", "Expirado"


class MfaResetCase(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_reset_cases",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="+",
    )
    request_verification = models.CharField(
        max_length=16,
        choices=RequestVerification.choices,
    )
    requested_at = models.DateTimeField(default=clock.default_now)

    opened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    request_channel = models.CharField(
        max_length=24,
        choices=RequestChannel.choices,
        null=True,
        blank=True,
    )
    opened_at = models.DateTimeField(null=True, blank=True)

    # Argon2id del código de 8 caracteres; se BORRA al autorizar o cancelar
    challenge_verifier = models.CharField(max_length=128, null=True, blank=True)
    challenge_expires_at = models.DateTimeField(null=True, blank=True)
    challenge_attempts = models.PositiveSmallIntegerField(default=0)

    status = models.CharField(
        max_length=24,
        choices=MfaResetStatus.choices,
        default=MfaResetStatus.REQUESTED,
    )

    authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    authorized_at = models.DateTimeField(null=True, blank=True)
    verification_method = models.CharField(max_length=64, null=True, blank=True)

    class Meta:
        db_table = "iam_mfaresetcase"
        indexes = [
            models.Index(fields=["status"], name="iam_mfareset_status_idx"),
            models.Index(fields=["target_user", "requested_at"], name="iam_mfareset_user_req_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["target_user"],
                condition=models.Q(status__in=[MfaResetStatus.REQUESTED, MfaResetStatus.PENDING_VERIFICATION]),
                name="iam_mfareset_one_open_per_user",
            ),
            models.CheckConstraint(
                condition=models.Q(challenge_attempts__lte=MAX_CHALLENGE_ATTEMPTS),
                name="iam_mfareset_max_attempts",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=MfaResetStatus.values),
                name="iam_mfareset_status_valid",
            ),
        ]

    def is_challenge_expired(self) -> bool:
        if not self.challenge_expires_at:
            return False
        return clock.now() >= self.challenge_expires_at

    def clear_challenge(self) -> None:
        """Borra el verificador del desafío para no persistir secretos hash innecesarios."""
        self.challenge_verifier = None
        self.challenge_expires_at = None

    def __str__(self) -> str:
        return f"MfaResetCase({self.id}, target={self.target_user_id}, status={self.status})"

