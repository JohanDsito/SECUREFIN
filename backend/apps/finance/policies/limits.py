from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.db.models import Sum
from django.utils import timezone

from apps.core import clock
from apps.finance.models import (
    FinancialLimit,
    FinancialTransaction,
    LimitKind,
    TransactionKind,
    TransactionStatus,
)

APPROVAL_THRESHOLDS = {
    "COP": (100_000_000, 500_000_000, 1_000_000_000),
    "USD": (25_000, 125_000, 250_000),
}


class LimitExceeded(ValueError):
    pass


@dataclass(frozen=True)
class LimitPolicy:
    per_transaction: int
    daily: int
    monthly: int
    frequency_count: int
    frequency_window_seconds: int


def _active_limit(currency: str, kind: str) -> FinancialLimit:
    try:
        return FinancialLimit.objects.get(
            scope_type="role",
            scope_id="client",
            currency=currency,
            limit_kind=kind,
            active=True,
        )
    except FinancialLimit.DoesNotExist as exc:
        raise RuntimeError(f"Falta la política financiera inicial {currency}/{kind}.") from exc


def get_policy(currency: str) -> LimitPolicy:
    per_transaction = _active_limit(currency, LimitKind.PER_TRANSACTION)
    daily = _active_limit(currency, LimitKind.DAILY)
    monthly = _active_limit(currency, LimitKind.MONTHLY)
    frequency = _active_limit(currency, LimitKind.FREQUENCY)
    return LimitPolicy(
        per_transaction=per_transaction.amount_minor,
        daily=daily.amount_minor,
        monthly=monthly.amount_minor,
        frequency_count=frequency.operation_count,
        frequency_window_seconds=frequency.period_seconds,
    )


def required_approvals(amount_minor: int, currency: str) -> int:
    try:
        thresholds = APPROVAL_THRESHOLDS[currency]
    except KeyError as exc:
        raise LimitExceeded("La moneda no está habilitada.") from exc
    for index, threshold in enumerate(thresholds):
        if amount_minor <= threshold:
            return index
    raise LimitExceeded("El importe supera el máximo permitido para la moneda.")


def _period_start(seconds: int):
    return clock.now() - timedelta(seconds=seconds)


def validate_transfer_limits(
    user,
    amount_minor: int,
    currency: str,
    *,
    exclude_transaction_id=None,
) -> int:
    policy = get_policy(currency)
    approvals = required_approvals(amount_minor, currency)
    if amount_minor > policy.per_transaction:
        raise LimitExceeded("El importe supera el límite por operación.")

    transactions = FinancialTransaction.objects.filter(
        creator=user,
        kind=TransactionKind.TRANSFER,
        currency=currency,
        status__in=[TransactionStatus.COMPLETED, TransactionStatus.PENDING_APPROVAL],
    )
    if exclude_transaction_id:
        transactions = transactions.exclude(pk=exclude_transaction_id)

    now = clock.now()
    day_start = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = day_start.replace(day=1)
    daily_total = transactions.filter(created_at__gte=day_start).aggregate(
        total=Sum("amount_minor")
    )["total"] or 0
    monthly_total = transactions.filter(created_at__gte=month_start).aggregate(
        total=Sum("amount_minor")
    )["total"] or 0
    recent_count = transactions.filter(
        created_at__gte=_period_start(policy.frequency_window_seconds)
    ).count()

    if daily_total + amount_minor > policy.daily:
        raise LimitExceeded("Se alcanzó el límite diario de la moneda.")
    if monthly_total + amount_minor > policy.monthly:
        raise LimitExceeded("Se alcanzó el límite mensual de la moneda.")
    if recent_count >= policy.frequency_count:
        raise LimitExceeded("Se alcanzó el límite de frecuencia de operaciones.")
    return approvals
