import uuid

import pytest

from apps.finance.models import Currency
from apps.finance.services.accounts import ensure_welcome_account
from apps.finance.services.transfers import create_transfer


@pytest.mark.contract
@pytest.mark.django_db
def test_transaction_filters_are_bounded_and_owner_scoped(login_as, make_user):
    client, user = login_as()
    recipient = make_user()
    source = ensure_welcome_account(user)
    destination = ensure_welcome_account(recipient)
    create_transfer(
        user, source.pk, destination.pk, 1_000, Currency.COP, "", str(uuid.uuid4())
    )

    all_rows = client.get("/finance/transactions")
    assert all_rows.status_code == 200
    assert all_rows.json()["count"] == 2
    assert all(row["currency"] == Currency.COP for row in all_rows.json()["results"])

    filtered = client.get("/finance/transactions?kind=transfer&currency=COP&page=1")
    assert filtered.status_code == 200
    assert filtered.json()["count"] == 1
    assert filtered.json()["results"][0]["kind"] == "transfer"

    no_foreign = client.get(f"/finance/transactions?account_id={destination.pk}")
    assert no_foreign.status_code == 200
    assert no_foreign.json()["count"] == 0

    invalid = client.get("/finance/transactions?from=not-a-date")
    assert invalid.status_code == 400
