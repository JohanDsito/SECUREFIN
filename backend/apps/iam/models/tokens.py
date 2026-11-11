"""Tokens de un solo uso con verificador HMAC-SHA-256 (T042; R7; data-model → OneTimeToken)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from apps.core import clock


class TokenPurpose(models.TextChoices):
    ACCOUNT_ACTIVATION = "account_activation", "Activación de cuenta (24 h)"
    PASSWORD_RESET = "password_reset", "Recuperación de contraseña (15 min, FR-046)"


class OneTimeToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tokens")
    purpose = models.CharField(max_length=24, choices=TokenPurpose.choices)
    verifier = models.CharField(max_length=64, unique=True)  # HMAC hex; el token nunca se guarda
    key_version = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=clock.default_now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True)
    invalidated_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "iam_onetimetoken"
        indexes = [models.Index(fields=["user", "purpose"], name="iam_token_user_purpose_idx")]

    def __str__(self) -> str:
        return f"OneTimeToken({self.id}, {self.purpose})"
