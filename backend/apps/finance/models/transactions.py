from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core import clock

from .accounts import Currency, DemoAccount


class TransactionKind(models.TextChoices):
    OPENING_CREDIT = "opening_credit", "Saldo ficticio inicial"
    TRANSFER = "transfer", "Transferencia simulada"
    REVERSAL = "reversal", "Reversión"


class TransactionStatus(models.TextChoices):
    PENDING_APPROVAL = "pending_approval", "Pendiente de aprobación"
    COMPLETED = "completed", "Completada"
    REJECTED = "rejected", "Rechazada"


class FinancialTransaction(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    correlation_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    kind = models.CharField(max_length=20, choices=TransactionKind.choices)
    status = models.CharField(max_length=20, choices=TransactionStatus.choices)
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="finance_transactions_created",
    )
    source_account = models.ForeignKey(
        DemoAccount,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="outgoing_transactions",
    )
    destination_account = models.ForeignKey(
        DemoAccount,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="incoming_transactions",
    )
    amount_minor = models.BigIntegerField()
    currency = models.CharField(max_length=3, choices=Currency.choices)
    description = models.CharField(max_length=140, blank=True, default="")
    idempotency_key = models.CharField(max_length=64, null=True, blank=True)
    request_fingerprint = models.CharField(max_length=64, null=True, blank=True)
    risk_level = models.CharField(max_length=10, blank=True, default="")
    risk_reasons = models.JSONField(default=list)
    approval_count_required = models.PositiveSmallIntegerField(default=0)
    rejection_reason = models.CharField(max_length=240, blank=True, default="")
    created_at = models.DateTimeField(default=clock.default_now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "finance_transaction"
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(condition=Q(amount_minor__gt=0), name="finance_tx_amount_positive"),
            models.CheckConstraint(
                condition=Q(currency__in=Currency.values), name="finance_tx_currency_valid"
            ),
            models.CheckConstraint(
                condition=Q(kind__in=TransactionKind.values), name="finance_tx_kind_valid"
            ),
            models.CheckConstraint(
                condition=Q(status__in=TransactionStatus.values), name="finance_tx_status_valid"
            ),
            models.CheckConstraint(
                condition=~Q(source_account=models.F("destination_account"))
                | Q(source_account__isnull=True),
                name="finance_tx_accounts_differ",
            ),
            models.UniqueConstraint(
                fields=["creator", "idempotency_key"],
                condition=Q(idempotency_key__isnull=False),
                name="finance_tx_creator_idempotency_uniq",
            ),
        ]
