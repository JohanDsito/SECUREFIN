from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import uuid

import pytest
from django.db import close_old_connections

from apps.finance.models import (
    AccountType,
    Currency,
    DemoAccount,
    FinancialTransaction,
    TransactionKind,
    TransactionStatus,
)
from apps.finance.services.ledger import LedgerLine, post_entries
from apps.finance.services.transfers import TransferError, create_transfer


@pytest.mark.security
def test_concurrent_transfers_do_not_spend_the_same_balance(make_user, concurrent_db):
    sender = make_user()
    recipient = make_user()
    source = DemoAccount.objects.create(
        owner=sender,
        masked_number="SF-DEMO-****-CA11",
        account_type=AccountType.CHECKING,
        currency=Currency.COP,
        available_balance_minor=0,
    )
    destination = DemoAccount.objects.create(
        owner=recipient,
        masked_number="SF-DEMO-****-CB22",
        account_type=AccountType.CHECKING,
        currency=Currency.COP,
    )
    clearing = DemoAccount.objects.create(
        owner=None,
        masked_number="SF-DEMO-CLEARING-COP",
        account_type=AccountType.CLEARING,
        currency=Currency.COP,
        is_system=True,
    )
    opening = FinancialTransaction.objects.create(
        kind=TransactionKind.OPENING_CREDIT,
        status=TransactionStatus.COMPLETED,
        creator=sender,
        source_account=clearing,
        destination_account=source,
        amount_minor=150_000_000,
        currency=Currency.COP,
    )
    post_entries(
        opening,
        [LedgerLine(clearing.pk, -150_000_000), LedgerLine(source.pk, 150_000_000)],
    )

    barrier = Barrier(2)

    def transfer(key):
        close_old_connections()
        barrier.wait()
        try:
            result = create_transfer(
                sender,
                source.pk,
                destination.pk,
                100_000_000,
                Currency.COP,
                "",
                key,
            )
            return result.status
        except TransferError:
            return "insufficient"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: transfer(str(uuid.uuid4())), range(2)))

    source.refresh_from_db()
    assert results.count(TransactionStatus.COMPLETED) == 1
    assert results.count("insufficient") == 1
    assert source.available_balance_minor == 50_000_000
