import uuid

import pytest

from apps.finance.models import Currency, LedgerEntry, TransactionStatus
from apps.finance.services.accounts import ensure_welcome_account, open_account
from apps.finance.services.transfers import (
    IdempotencyConflict,
    TransferAccountNotFound,
    TransferError,
    create_transfer,
    preview_transfer,
)


@pytest.mark.integration
@pytest.mark.django_db
def test_transfer_posts_balanced_entries_and_is_idempotent(make_user):
    sender = make_user()
    recipient = make_user()
    source = ensure_welcome_account(sender)
    destination = ensure_welcome_account(recipient)
    key = str(uuid.uuid4())

    preview = preview_transfer(
        sender, source.pk, destination.pk, 10_000, Currency.COP, "Pago de prueba"
    )
    assert preview["fee_minor"] == 0
    assert preview["status"] == TransactionStatus.COMPLETED
    source.refresh_from_db()
    assert source.available_balance_minor == 500_000_000

    result = create_transfer(
        sender, source.pk, destination.pk, 10_000, Currency.COP, "Pago de prueba", key
    )
    retry = create_transfer(
        sender, source.pk, destination.pk, 10_000, Currency.COP, "Pago de prueba", key
    )

    source.refresh_from_db()
    destination.refresh_from_db()
    entries = list(LedgerEntry.objects.filter(transaction=result))
    assert result.status == TransactionStatus.COMPLETED
    assert retry.pk == result.pk
    assert source.available_balance_minor == 499_990_000
    assert destination.available_balance_minor == 500_010_000
    assert len(entries) == 2
    assert sum(entry.amount_minor for entry in entries) == 0

    with pytest.raises(IdempotencyConflict):
        create_transfer(
            sender, source.pk, destination.pk, 11_000, Currency.COP, "Pago de prueba", key
        )

    source.refresh_from_db()
    destination.refresh_from_db()
    assert source.available_balance_minor == 499_990_000
    assert destination.available_balance_minor == 500_010_000


@pytest.mark.integration
@pytest.mark.django_db
def test_transfer_over_auto_threshold_waits_for_approval_without_debit(make_user):
    sender = make_user()
    recipient = make_user()
    source = ensure_welcome_account(sender)
    destination = ensure_welcome_account(recipient)

    result = create_transfer(
        sender,
        source.pk,
        destination.pk,
        100_000_001,
        Currency.COP,
        "Transferencia pendiente",
        str(uuid.uuid4()),
    )

    source.refresh_from_db()
    destination.refresh_from_db()
    assert result.status == TransactionStatus.PENDING_APPROVAL
    assert result.approval_count_required == 1
    assert source.available_balance_minor == 500_000_000
    assert destination.available_balance_minor == 500_000_000
    assert not LedgerEntry.objects.filter(transaction=result).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_transfer_rejects_foreign_source_same_account_and_insufficient_balance(make_user):
    sender = make_user()
    other = make_user()
    source = ensure_welcome_account(sender)
    foreign = ensure_welcome_account(other)

    with pytest.raises(TransferAccountNotFound):
        create_transfer(
            sender, foreign.pk, source.pk, 100, Currency.COP, "", str(uuid.uuid4())
        )
    with pytest.raises(TransferError):
        create_transfer(
            sender, source.pk, source.pk, 100, Currency.COP, "", str(uuid.uuid4())
        )

    empty_source = open_account(sender, Currency.USD, "checking")
    empty_destination = open_account(other, Currency.USD, "checking")
    with pytest.raises(TransferError, match="Saldo insuficiente"):
        create_transfer(
            sender,
            empty_source.pk,
            empty_destination.pk,
            1,
            Currency.USD,
            "",
            str(uuid.uuid4()),
        )
