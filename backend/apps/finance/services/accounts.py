from __future__ import annotations

import hashlib
import uuid

from django.db import transaction

from apps.core import clock
from apps.finance.models import (
    AccountStatus,
    AccountType,
    Currency,
    DemoAccount,
    FinancialTransaction,
    TransactionKind,
    TransactionStatus,
)
from apps.finance.policies.permissions import FinancePermissionDenied, require_permission
from apps.finance.services.ledger import LedgerLine, post_entries
from apps.finance.services.audit import record_finance_event
from apps.iam.models import Role, User

WELCOME_AMOUNT_MINOR = 500_000_000
WELCOME_IDEMPOTENCY_KEY = "securefin-welcome-v1"


class InvalidAccountRequest(ValueError):
    pass


def _masked_number() -> str:
    return f"SF-DEMO-****-{uuid.uuid4().hex[-4:].upper()}"


def _require_client(user) -> None:
    require_permission(user, "finance.accounts.self")
    if user.role != Role.CLIENT:
        raise FinancePermissionDenied("Las cuentas personales solo están disponibles para Clientes.")


def _clearing_account(currency: str) -> DemoAccount:
    account, _ = DemoAccount.objects.get_or_create(
        is_system=True,
        currency=currency,
        defaults={
            "owner": None,
            "masked_number": f"SF-DEMO-CLEARING-{currency}",
            "account_type": AccountType.CLEARING,
            "status": AccountStatus.ACTIVE,
        },
    )
    return account


def ensure_welcome_account(user) -> DemoAccount:
    _require_client(user)
    with transaction.atomic():
        User.objects.select_for_update().get(pk=user.pk)
        existing = DemoAccount.objects.filter(owner=user, is_welcome=True).first()
        if existing:
            return existing

        account = DemoAccount.objects.create(
            owner=user,
            masked_number=_masked_number(),
            account_type=AccountType.SAVINGS,
            currency=Currency.COP,
            available_balance_minor=0,
            status=AccountStatus.ACTIVE,
            is_welcome=True,
        )
        clearing = _clearing_account(Currency.COP)
        fingerprint = hashlib.sha256(
            f"{user.pk}:{WELCOME_IDEMPOTENCY_KEY}:{WELCOME_AMOUNT_MINOR}:COP".encode()
        ).hexdigest()
        financial_transaction = FinancialTransaction.objects.create(
            kind=TransactionKind.OPENING_CREDIT,
            status=TransactionStatus.COMPLETED,
            creator=user,
            source_account=clearing,
            destination_account=account,
            amount_minor=WELCOME_AMOUNT_MINOR,
            currency=Currency.COP,
            description="Saldo ficticio inicial de SecureFin",
            idempotency_key=WELCOME_IDEMPOTENCY_KEY,
            request_fingerprint=fingerprint,
            risk_level="low",
            resolved_at=clock.now(),
        )
        post_entries(
            financial_transaction,
            [
                LedgerLine(clearing.pk, -WELCOME_AMOUNT_MINOR),
                LedgerLine(account.pk, WELCOME_AMOUNT_MINOR),
            ],
        )
        record_finance_event(
            "finance_account_welcome_credited",
            "success",
            actor=user,
            target_type="finance_account",
            target_id=account.pk,
            metadata={
                "account_id": account.pk,
                "amount_minor": WELCOME_AMOUNT_MINOR,
                "currency": Currency.COP,
                "correlation_id": financial_transaction.correlation_id,
            },
        )
        account.refresh_from_db()
        return account


def open_account(user, currency: str, account_type: str) -> DemoAccount:
    _require_client(user)
    if currency not in Currency.values:
        raise InvalidAccountRequest("Moneda no admitida.")
    if account_type not in (AccountType.CHECKING, AccountType.SAVINGS):
        raise InvalidAccountRequest("Tipo de cuenta no admitido.")

    with transaction.atomic():
        account = DemoAccount.objects.create(
            owner=user,
            masked_number=_masked_number(),
            account_type=account_type,
            currency=currency,
            available_balance_minor=0,
            status=AccountStatus.ACTIVE,
        )
        record_finance_event(
            "finance_account_opened",
            "success",
            actor=user,
            target_type="finance_account",
            target_id=account.pk,
            metadata={
                "account_id": account.pk,
                "currency": account.currency,
                "account_type": account.account_type,
            },
        )
        return account
