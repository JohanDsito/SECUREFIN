from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core import clock

from .accounts import AccountStatus, Currency, DemoAccount
from .transactions import FinancialTransaction


class Decision(models.TextChoices):
    APPROVED = "approved", "Aprobada"
    REJECTED = "rejected", "Rechazada"


class ScopeType(models.TextChoices):
    USER = "user", "Usuario"
    ROLE = "role", "Rol"
    OPERATION = "operation", "Operación"


class LimitKind(models.TextChoices):
    PER_TRANSACTION = "per_transaction", "Por operación"
    DAILY = "daily", "Diario"
    MONTHLY = "monthly", "Mensual"
    FREQUENCY = "frequency", "Frecuencia"


class RiskAction(models.TextChoices):
    ALLOW = "allow", "Permitir"
    MFA = "mfa", "Solicitar MFA"
    REVIEW = "review", "Revisión administrativa"
    REJECT = "reject", "Rechazar"


class RiskLevel(models.TextChoices):
    LOW = "low", "Bajo"
    MEDIUM = "medium", "Medio"
    HIGH = "high", "Alto"
    CRITICAL = "critical", "Crítico"


class NotificationKind(models.TextChoices):
    TRANSFER_CREATED = "transfer_created", "Transferencia creada"
    APPROVAL_REQUIRED = "approval_required", "Aprobación requerida"
    TRANSFER_COMPLETED = "transfer_completed", "Transferencia completada"
    TRANSFER_REJECTED = "transfer_rejected", "Transferencia rechazada"
    LIMIT_REACHED = "limit_reached", "Límite alcanzado"
    RISK_ALERT = "risk_alert", "Alerta de riesgo"
    LIMIT_CHANGED = "limit_changed", "Límite modificado"


class LedgerEntry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.ForeignKey(
        FinancialTransaction, on_delete=models.PROTECT, related_name="ledger_entries"
    )
    account = models.ForeignKey(DemoAccount, on_delete=models.PROTECT, related_name="ledger_entries")
    currency = models.CharField(max_length=3, choices=Currency.choices)
    amount_minor = models.BigIntegerField()
    created_at = models.DateTimeField(default=clock.default_now, editable=False)

    class Meta:
        db_table = "finance_ledgerentry"
        ordering = ["created_at", "id"]
        constraints = [
            models.CheckConstraint(
                condition=Q(currency__in=Currency.values), name="finance_entry_currency_valid"
            ),
            models.CheckConstraint(condition=~Q(amount_minor=0), name="finance_entry_amount_nonzero"),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise RuntimeError("Los asientos del libro no se pueden modificar.")
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("Los asientos del libro no se pueden borrar.")


class ApprovalDecision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.ForeignKey(
        FinancialTransaction, on_delete=models.PROTECT, related_name="decisions"
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="finance_decisions"
    )
    decision = models.CharField(max_length=10, choices=Decision.choices)
    request_fingerprint = models.CharField(max_length=64)
    reason = models.CharField(max_length=240, blank=True, default="")
    created_at = models.DateTimeField(default=clock.default_now)

    class Meta:
        db_table = "finance_approvaldecision"
        constraints = [
            models.UniqueConstraint(
                fields=["transaction", "approver"], name="finance_decision_one_per_approver"
            ),
            models.CheckConstraint(
                condition=Q(decision__in=Decision.values), name="finance_decision_valid"
            ),
        ]


class FinancialLimit(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scope_type = models.CharField(max_length=12, choices=ScopeType.choices)
    scope_id = models.CharField(max_length=100, blank=True, default="")
    currency = models.CharField(max_length=3, choices=Currency.choices)
    limit_kind = models.CharField(max_length=20, choices=LimitKind.choices)
    amount_minor = models.BigIntegerField(null=True, blank=True)
    operation_count = models.PositiveIntegerField(null=True, blank=True)
    period_seconds = models.PositiveIntegerField(null=True, blank=True)
    active = models.BooleanField(default=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    updated_at = models.DateTimeField(default=clock.default_now)
    reason = models.CharField(max_length=240, blank=True, default="")

    class Meta:
        db_table = "finance_financiallimit"
        constraints = [
            models.CheckConstraint(
                condition=Q(currency__in=Currency.values), name="finance_limit_currency_valid"
            ),
            models.CheckConstraint(
                condition=Q(amount_minor__gt=0) | Q(operation_count__gt=0),
                name="finance_limit_value_positive",
            ),
        ]


class RiskRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=40, unique=True)
    enabled = models.BooleanField(default=True)
    threshold = models.PositiveBigIntegerField(default=1)
    window_seconds = models.PositiveIntegerField(default=3600)
    action = models.CharField(max_length=10, choices=RiskAction.choices)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    updated_at = models.DateTimeField(default=clock.default_now)

    class Meta:
        db_table = "finance_riskrule"
        constraints = [
            models.CheckConstraint(
                condition=Q(action__in=RiskAction.values), name="finance_riskrule_action_valid"
            )
        ]


class RiskAlert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.ForeignKey(
        FinancialTransaction, on_delete=models.PROTECT, related_name="risk_alerts"
    )
    rule_code = models.CharField(max_length=40)
    severity = models.CharField(max_length=10, choices=RiskLevel.choices)
    reason = models.CharField(max_length=240)
    status = models.CharField(max_length=12, default="open")
    created_at = models.DateTimeField(default=clock.default_now)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "finance_riskalert"
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=Q(severity__in=RiskLevel.values), name="finance_alert_severity_valid"
            )
        ]


class DemoCard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="finance_demo_cards"
    )
    display_alias = models.CharField(max_length=32)
    status = models.CharField(max_length=8, choices=AccountStatus.choices, default=AccountStatus.ACTIVE)
    created_at = models.DateTimeField(default=clock.default_now)
    updated_at = models.DateTimeField(default=clock.default_now)

    class Meta:
        db_table = "finance_democard"
        constraints = [
            models.CheckConstraint(
                condition=Q(status__in=AccountStatus.values), name="finance_card_status_valid"
            )
        ]


class FinancialNotification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="finance_notifications"
    )
    kind = models.CharField(max_length=24, choices=NotificationKind.choices)
    transaction = models.ForeignKey(
        FinancialTransaction, null=True, blank=True, on_delete=models.PROTECT
    )
    message = models.CharField(max_length=240)
    created_at = models.DateTimeField(default=clock.default_now)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "finance_notification"
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=Q(kind__in=NotificationKind.values),
                name="finance_notification_kind_valid",
            )
        ]
