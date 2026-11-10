import uuid

import pytest

from apps.finance.models import Currency
from apps.finance.services.accounts import ensure_welcome_account
from apps.finance.services.transfers import create_transfer
from apps.iam.models import Role


@pytest.mark.contract
@pytest.mark.django_db
def test_admin_mfa_approval_queue_and_auditor_read_only(login_as, make_user):
    sender = make_user()
    recipient = make_user()
    source = ensure_welcome_account(sender)
    destination = ensure_welcome_account(recipient)
    pending = create_transfer(
        sender,
        source.pk,
        destination.pk,
        100_000_001,
        Currency.COP,
        "Revisión administrativa",
        str(uuid.uuid4()),
    )
    admin_client, _ = login_as(role=Role.ADMIN)
    auditor_client, _ = login_as(role=Role.AUDITOR)

    queue = auditor_client.get("/admin/finance/approvals")
    assert queue.status_code == 200
    assert queue.json()[0]["id"] == str(pending.pk)
    denied = auditor_client.post(
        f"/admin/finance/transfers/{pending.pk}/approve", {}
    )
    assert denied.status_code == 403

    approved = admin_client.post(
        f"/admin/finance/transfers/{pending.pk}/approve", {}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "completed"
