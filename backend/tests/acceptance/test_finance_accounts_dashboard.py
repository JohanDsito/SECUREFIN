import pytest

from apps.finance.models import Currency
from apps.finance.services.accounts import ensure_welcome_account


@pytest.mark.acceptance
@pytest.mark.django_db
def test_accounts_dashboard_isolated_by_owner_and_balances_by_currency(login_as):
    client_a, user_a = login_as()
    client_b, user_b = login_as()
    account_a = ensure_welcome_account(user_a)
    account_b = ensure_welcome_account(user_b)

    dashboard = client_a.get("/finance/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["balances"] == {"COP": 500_000_000, "USD": 0}
    assert [row["id"] for row in dashboard.json()["accounts"]] == [str(account_a.pk)]

    foreign_detail = client_a.get(f"/finance/accounts/{account_b.pk}")
    assert foreign_detail.status_code == 404

    opened = client_a.post(
        "/finance/accounts", {"type": "checking", "currency": Currency.USD}
    )
    assert opened.status_code == 201
    assert opened.json()["available_balance_minor"] == 0
    assert opened.json()["currency"] == Currency.USD

    own_detail = client_a.get(f"/finance/accounts/{opened.json()['id']}")
    assert own_detail.status_code == 200
    assert own_detail.json()["masked_number"].startswith("SF-DEMO-****-")
    assert user_a.pk != user_b.pk
