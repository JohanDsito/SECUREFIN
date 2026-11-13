import pytest
from django.db import DatabaseError, connection, transaction

from apps.finance.models import (
    AccountStatus,
    Currency,
    DemoAccount,
    FinancialTransaction,
    LedgerEntry,
    TransactionKind,
    TransactionStatus,
)
from apps.finance.services.accounts import ensure_welcome_account
from apps.finance.services.ledger import InvalidLedgerPosting, LedgerLine, post_entries


@pytest.mark.integration
@pytest.mark.django_db
def test_postgres_ledger_trigger_rejects_update_and_delete(make_user):
    user = make_user()
    account = ensure_welcome_account(user)
    entry = LedgerEntry.objects.get(account=account)

    with pytest.raises(DatabaseError):
        with transaction.atomic():
            LedgerEntry.objects.filter(pk=entry.pk).update(amount_minor=entry.amount_minor + 1)

    with pytest.raises(DatabaseError):
        with transaction.atomic():
            LedgerEntry.objects.filter(pk=entry.pk).delete()


@pytest.mark.integration
@pytest.mark.django_db
def test_postgres_ledger_role_can_read_insert_but_not_mutate():
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", ["securefin_app"])
        if cursor.fetchone() is None:
            pytest.skip("El rol securefin_app no existe en esta base de prueba.")
        cursor.execute(
            """
            SELECT has_table_privilege('securefin_app', 'finance_ledgerentry', 'SELECT'),
                   has_table_privilege('securefin_app', 'finance_ledgerentry', 'INSERT'),
                   has_table_privilege('securefin_app', 'finance_ledgerentry', 'UPDATE'),
                   has_table_privilege('securefin_app', 'finance_ledgerentry', 'DELETE'),
                   has_table_privilege('securefin_app', 'finance_ledgerentry', 'TRUNCATE')
            """
        )
        can_select, can_insert, can_update, can_delete, can_truncate = cursor.fetchone()

    assert can_select is True
    assert can_insert is True
    assert can_update is False
    assert can_delete is False
    assert can_truncate is False


@pytest.mark.integration
@pytest.mark.django_db
def test_ledger_posting_failure_rolls_back_all_balance_updates(make_user):
    user = make_user()
    source = DemoAccount.objects.create(
        owner=user,
        masked_number="SF-DEMO-****-1001",
        account_type="checking",
        currency=Currency.COP,
        available_balance_minor=100,
    )
    destination = DemoAccount.objects.create(
        owner=user,
        masked_number="SF-DEMO-****-1002",
        account_type="checking",
        currency=Currency.COP,
        status=AccountStatus.FROZEN,
    )
    financial_transaction = FinancialTransaction.objects.create(
        kind=TransactionKind.TRANSFER,
        status=TransactionStatus.COMPLETED,
        creator=user,
        source_account=source,
        destination_account=destination,
        amount_minor=100,
        currency=Currency.COP,
    )

    with pytest.raises(InvalidLedgerPosting):
        post_entries(
            financial_transaction,
            [LedgerLine(source.pk, -100), LedgerLine(destination.pk, 100)],
        )

    source.refresh_from_db()
    destination.refresh_from_db()
    assert source.available_balance_minor == 100
    assert destination.available_balance_minor == 0
    assert not LedgerEntry.objects.filter(transaction=financial_transaction).exists()
