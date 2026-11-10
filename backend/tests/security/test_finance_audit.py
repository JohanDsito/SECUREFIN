import pytest

from apps.audit.services import AuditError, _check_metadata


@pytest.mark.unit
def test_finance_audit_rejects_card_secrets_and_unapproved_metadata():
    with pytest.raises(AuditError):
        _check_metadata("finance_card_created", {"card_id": "demo", "pan": "4111111111111111"})
    with pytest.raises(AuditError):
        _check_metadata("finance_card_created", {"card_id": "demo", "cvv": "123"})


@pytest.mark.unit
def test_finance_audit_allows_only_minimal_allowlisted_data():
    assert _check_metadata(
        "finance_transfer_completed",
        {"transaction_id": "internal-id", "amount_minor": 100, "currency": "COP"},
    ) == {"transaction_id": "internal-id", "amount_minor": 100, "currency": "COP"}
