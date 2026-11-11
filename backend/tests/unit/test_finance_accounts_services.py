import pytest

from apps.finance.models import (
    Currency,
    DemoAccount,
    FinancialTransaction,
    LedgerEntry,
)
from apps.finance.services.accounts import ensure_welcome_account, open_account
from apps.finance.services.ledger import InvalidLedgerPosting, LedgerLine, post_entries


@pytest.mark.django_db
def test_welcome_account_is_idempotent_and_balanced(make_user):
    user = make_user()

    account = ensure_welcome_account(user)
    retry = ensure_welcome_account(user)

    assert retry.pk == account.pk
    assert account.currency == Currency.COP
    assert account.available_balance_minor == 500_000_000
    assert DemoAccount.objects.filter(owner=user, is_welcome=True).count() == 1
    financial_transaction = FinancialTransaction.objects.get(
        creator=user, idempotency_key="securefin-welcome-v1"
    )
    entries = list(LedgerEntry.objects.filter(transaction=financial_transaction))
    assert len(entries) == 2
    assert sum(entry.amount_minor for entry in entries) == 0
    assert sum(entry.amount_minor for entry in entries if entry.amount_minor > 0) == 500_000_000


@pytest.mark.django_db
def test_additional_accounts_start_at_zero(make_user):
    user = make_user()

    account = open_account(user, Currency.USD, "checking")

    assert account.owner_id == user.pk
    assert account.currency == Currency.USD
    assert account.available_balance_minor == 0
    assert account.is_welcome is False
    assert account.masked_number.startswith("SF-DEMO-****-")


@pytest.mark.unit
def test_ledger_rejects_unbalanced_lines_before_writing():
    from apps.finance.models import FinancialTransaction, TransactionStatus

    pending = FinancialTransaction(status=TransactionStatus.COMPLETED, amount_minor=100)

    with pytest.raises(InvalidLedgerPosting):
        post_entries(
            pending,
            [LedgerLine("source", -100), LedgerLine("destination", 99)],
        )


@pytest.mark.django_db
def test_client_cannot_open_an_account_for_another_role(make_user):
    from apps.finance.policies.permissions import FinancePermissionDenied

    admin = make_user(role="admin")

    with pytest.raises(FinancePermissionDenied):
        open_account(admin, Currency.COP, "checking")


@pytest.mark.unit
def test_ledger_rejects_non_completed_transactions():
    from apps.finance.models import FinancialTransaction, TransactionStatus

    pending = FinancialTransaction(status=TransactionStatus.PENDING_APPROVAL, amount_minor=100)

    with pytest.raises(InvalidLedgerPosting):
        post_entries(pending, [LedgerLine("source", -100), LedgerLine("destination", 100)])
