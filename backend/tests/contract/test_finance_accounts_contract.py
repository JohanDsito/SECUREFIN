import pytest


@pytest.mark.contract
@pytest.mark.django_db
def test_account_api_requires_auth_and_rejects_client_controlled_fields(api_factory, login_as):
    anonymous = api_factory()
    assert anonymous.get("/finance/accounts").status_code == 401

    client, _ = login_as()
    response = client.post(
        "/finance/accounts",
        {"type": "checking", "currency": "USD", "available_balance_minor": 900_000_000},
    )
    assert response.status_code == 400

    response = client.post("/finance/accounts", {"type": "checking", "currency": "USD"})
    assert response.status_code == 201
    account = response.json()
    assert account["available_balance_minor"] == 0
    assert set(account) == {
        "id",
        "masked_number",
        "type",
        "currency",
        "available_balance_minor",
        "status",
        "created_at",
    }


@pytest.mark.contract
@pytest.mark.django_db
def test_account_mutation_rejects_missing_csrf(api_factory, login_as):
    authenticated, user = login_as()
    client = api_factory()
    client.client.cookies.update(authenticated.client.cookies)
    client.fetch_csrf()

    response = client.post(
        "/finance/accounts",
        {"type": "checking", "currency": "COP"},
        csrf=False,
    )
    assert response.status_code == 403
    assert user.finance_accounts.count() == 0
