import uuid

import pytest

from apps.finance.models import Currency, LedgerEntry, TransactionStatus
from apps.finance.services.accounts import ensure_welcome_account
from apps.finance.services.approvals import ApprovalError, decide_transfer
from apps.finance.services.transfers import create_transfer
from apps.iam.models import Role


@pytest.mark.acceptance
@pytest.mark.django_db
def test_one_admin_approval_posts_once_and_creator_cannot_approve(login_as, make_user):
    client, creator = login_as()
    recipient = make_user()
    source = ensure_welcome_account(creator)
    destination = ensure_welcome_account(recipient)
    transfer = create_transfer(
        creator,
        source.pk,
        destination.pk,
        100_000_001,
        Currency.COP,
        "Requiere aprobación",
        str(uuid.uuid4()),
    )
    assert transfer.status == TransactionStatus.PENDING_APPROVAL

    with pytest.raises(ApprovalError):
        decide_transfer(creator, transfer.pk, "approved")

    _, admin = login_as(role=Role.ADMIN)
    completed = decide_transfer(admin, transfer.pk, "approved")
    assert completed.status == TransactionStatus.COMPLETED
    assert LedgerEntry.objects.filter(transaction=transfer).count() == 2
    source.refresh_from_db()
    destination.refresh_from_db()
    assert source.available_balance_minor == 399_999_999
    assert destination.available_balance_minor == 600_000_001

    with pytest.raises(ApprovalError):
        decide_transfer(admin, transfer.pk, "approved")
    assert LedgerEntry.objects.filter(transaction=transfer).count() == 2


@pytest.mark.acceptance
@pytest.mark.django_db
def test_two_distinct_admins_are_required_for_large_transfer(login_as, make_user):
    sender_client, sender = login_as()
    funder = make_user()
    recipient = make_user()
    source = ensure_welcome_account(sender)
    funder_account = ensure_welcome_account(funder)
    destination = ensure_welcome_account(recipient)
    create_transfer(
        funder,
        funder_account.pk,
        source.pk,
        10_000_000,
        Currency.COP,
        "Abono ficticio",
        str(uuid.uuid4()),
    )
    transfer = create_transfer(
        sender,
        source.pk,
        destination.pk,
        505_000_000,
        Currency.COP,
        "Requiere dos aprobadores",
        str(uuid.uuid4()),
    )
    _, first_admin = login_as(role=Role.ADMIN)
    _, second_admin = login_as(role=Role.ADMIN)

    first_result = decide_transfer(first_admin, transfer.pk, "approved")
    assert first_result.status == TransactionStatus.PENDING_APPROVAL
    assert not LedgerEntry.objects.filter(transaction=transfer).exists()

    completed = decide_transfer(second_admin, transfer.pk, "approved")
    assert completed.status == TransactionStatus.COMPLETED
    assert LedgerEntry.objects.filter(transaction=transfer).count() == 2
    source.refresh_from_db()
    destination.refresh_from_db()
    assert source.available_balance_minor == 5_000_000
    assert destination.available_balance_minor == 1_005_000_000
