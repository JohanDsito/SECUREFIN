import uuid

import pytest

from apps.finance.services.accounts import ensure_welcome_account


@pytest.mark.contract
@pytest.mark.django_db
def test_transfer_contract_requires_idempotency_and_returns_same_result(login_as, make_user):
    sender_client, sender = login_as()
    recipient = make_user()
    source = ensure_welcome_account(sender)
    destination = ensure_welcome_account(recipient)
    payload = {
        "source_account_id": str(source.pk),
        "destination_account_id": str(destination.pk),
        "amount_minor": 1_000,
        "currency": "COP",
        "description": "Pago API de prueba",
    }

    preview = sender_client.post("/finance/transfers/preview", payload)
    assert preview.status_code == 200
    assert preview.json()["fee_minor"] == 0

    missing_key = sender_client.post("/finance/transfers", payload)
    assert missing_key.status_code == 400

    key = str(uuid.uuid4())
    first = sender_client.post("/finance/transfers", payload, HTTP_IDEMPOTENCY_KEY=key)
    retry = sender_client.post("/finance/transfers", payload, HTTP_IDEMPOTENCY_KEY=key)
    assert first.status_code == 201
    assert retry.status_code == 201
    assert retry.json()["id"] == first.json()["id"]

    changed_payload = {**payload, "amount_minor": 2_000}
    conflict = sender_client.post(
        "/finance/transfers", changed_payload, HTTP_IDEMPOTENCY_KEY=key
    )
    assert conflict.status_code == 409
