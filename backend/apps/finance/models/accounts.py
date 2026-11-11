from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core import clock


class Currency(models.TextChoices):
    COP = "COP", "Peso colombiano"
    USD = "USD", "Dólar estadounidense"


class AccountType(models.TextChoices):
    CHECKING = "checking", "Cuenta corriente"
    SAVINGS = "savings", "Cuenta de ahorros"
    CLEARING = "clearing", "Fondos ficticios"


class AccountStatus(models.TextChoices):
    ACTIVE = "active", "Activa"
    FROZEN = "frozen", "Congelada"
    CLOSED = "closed", "Cerrada"


class DemoAccount(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="finance_accounts",
    )
    masked_number = models.CharField(max_length=32)
    account_type = models.CharField(max_length=12, choices=AccountType.choices)
    currency = models.CharField(max_length=3, choices=Currency.choices)
    available_balance_minor = models.BigIntegerField(default=0)
    status = models.CharField(max_length=8, choices=AccountStatus.choices, default=AccountStatus.ACTIVE)
    is_system = models.BooleanField(default=False)
    is_welcome = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=clock.default_now)
    updated_at = models.DateTimeField(default=clock.default_now)

    class Meta:
        db_table = "finance_demoaccount"
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=Q(available_balance_minor__gte=0) | Q(is_system=True),
                name="finance_account_user_balance_nonnegative",
            ),
            models.CheckConstraint(
                condition=Q(currency__in=Currency.values),
                name="finance_account_currency_valid",
            ),
            models.CheckConstraint(
                condition=Q(account_type__in=AccountType.values),
                name="finance_account_type_valid",
            ),
            models.CheckConstraint(
                condition=Q(status__in=AccountStatus.values),
                name="finance_account_status_valid",
            ),
            models.CheckConstraint(
                condition=Q(is_system=True, owner__isnull=True)
                | Q(is_system=False, owner__isnull=False),
                name="finance_account_system_owner_consistent",
            ),
            models.UniqueConstraint(
                fields=["owner"],
                condition=Q(is_welcome=True, is_system=False),
                name="finance_account_one_welcome_per_owner",
            ),
            models.UniqueConstraint(
                fields=["currency"],
                condition=Q(is_system=True),
                name="finance_account_one_clearing_per_currency",
            ),
        ]
        indexes = [models.Index(fields=["owner", "status"], name="finance_account_owner_status")]
