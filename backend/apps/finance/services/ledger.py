from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from django.db import transaction

from apps.core import clock

from apps.finance.models import AccountStatus, DemoAccount, FinancialTransaction, LedgerEntry


class InvalidLedgerPosting(ValueError):
    pass


class InsufficientFunds(ValueError):
    pass


@dataclass(frozen=True)
class LedgerLine:
    account_id: object
    amount_minor: int


def post_entries(financial_transaction: FinancialTransaction, lines: Iterable[LedgerLine]) -> list[LedgerEntry]:
    lines = list(lines)
    if len(lines) < 2:
        raise InvalidLedgerPosting("Un asiento financiero requiere al menos dos líneas.")
    if financial_transaction.status != "completed":
        raise InvalidLedgerPosting("Solo se pueden registrar asientos de operaciones completadas.")
    if any(not isinstance(line.amount_minor, int) or line.amount_minor == 0 for line in lines):
        raise InvalidLedgerPosting("Cada línea debe contener un importe entero distinto de cero.")
    if sum(line.amount_minor for line in lines) != 0:
        raise InvalidLedgerPosting("Los asientos deben estar balanceados.")
    if sum(line.amount_minor for line in lines if line.amount_minor > 0) != financial_transaction.amount_minor:
        raise InvalidLedgerPosting("El total de crédito debe coincidir con la operación.")
    account_ids = [line.account_id for line in lines]
    if len(set(account_ids)) != len(account_ids):
        raise InvalidLedgerPosting("Una operación no puede repetir cuentas en sus asientos.")

    with transaction.atomic():
        accounts = {
            account.pk: account
            for account in DemoAccount.objects.select_for_update()
            .filter(pk__in=account_ids)
            .order_by("pk")
        }
        if len(accounts) != len(account_ids):
            raise InvalidLedgerPosting("No se encontró una cuenta de la operación.")

        for line in lines:
            account = accounts[line.account_id]
            if account.status != AccountStatus.ACTIVE:
                raise InvalidLedgerPosting("No se puede registrar una operación en una cuenta inactiva.")
            if account.currency != financial_transaction.currency:
                raise InvalidLedgerPosting("La moneda del asiento no coincide con la operación.")
            next_balance = account.available_balance_minor + line.amount_minor
            if not account.is_system and next_balance < 0:
                raise InsufficientFunds("Saldo insuficiente.")
            account.available_balance_minor = next_balance
            account.updated_at = clock.now()
            account.save(update_fields=["available_balance_minor", "updated_at"])

        return LedgerEntry.objects.bulk_create(
            [
                LedgerEntry(
                    transaction=financial_transaction,
                    account=accounts[line.account_id],
                    currency=financial_transaction.currency,
                    amount_minor=line.amount_minor,
                )
                for line in lines
            ]
        )
