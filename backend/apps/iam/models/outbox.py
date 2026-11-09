"""Outbox de correo sin secretos (T043; R9; data-model → OutboxMessage).

No tiene campos de token, código ni cuerpo de correo: el secreto se genera en memoria en el momento
de la entrega (proceso `mailer`).
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from apps.core import clock

MAX_ATTEMPTS = 5


class OutboxKind(models.TextChoices):
    ACCOUNT_ACTIVATION = "account_activation"
    PASSWORD_RESET = "password_reset"
    MFA_RESET_CHALLENGE = "mfa_reset_challenge"
    MFA_RESET_NOTICE = "mfa_reset_notice"


class OutboxStatus(models.TextChoices):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


class OutboxMessage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=24, choices=OutboxKind.choices)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    related_id = models.UUIDField(null=True)
    status = models.CharField(max_length=10, choices=OutboxStatus.choices, default=OutboxStatus.PENDING)
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=clock.default_now)
    created_at = models.DateTimeField(default=clock.default_now)
    sent_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "iam_outboxmessage"
        indexes = [models.Index(fields=["status", "next_attempt_at"], name="iam_outbox_due_idx")]
        constraints = [
            models.CheckConstraint(condition=models.Q(attempts__lte=MAX_ATTEMPTS), name="iam_outbox_max_attempts")
        ]
