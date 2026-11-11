import pytest


@pytest.mark.unit
def test_finance_accounts_use_supported_currencies_and_nonnegative_balances():
    from apps.finance.models import AccountStatus, AccountType, Currency, DemoAccount

    field = DemoAccount._meta.get_field("currency")
    assert {value for value, _ in field.choices} == {Currency.COP, Currency.USD}
    constraints = {constraint.name for constraint in DemoAccount._meta.constraints}
    assert "finance_account_user_balance_nonnegative" in constraints
    assert "finance_account_system_owner_consistent" in constraints
    assert {
        value for value, _ in DemoAccount._meta.get_field("account_type").choices
    } == set(AccountType.values)
    assert {value for value, _ in DemoAccount._meta.get_field("status").choices} == set(
        AccountStatus.values
    )


@pytest.mark.unit
def test_financial_ledger_entries_are_marked_immutable():
    from apps.finance.models import FinancialTransaction, LedgerEntry, TransactionKind

    assert LedgerEntry._meta.get_field("amount_minor").get_internal_type() == "BigIntegerField"
    assert LedgerEntry._meta.get_field("created_at").editable is False
    assert "finance_tx_creator_idempotency_uniq" in {
        constraint.name for constraint in FinancialTransaction._meta.constraints
    }
    assert {
        value for value, _ in FinancialTransaction._meta.get_field("kind").choices
    } == set(TransactionKind.values)

    entry = LedgerEntry(amount_minor=1)
    entry._state.adding = False
    with pytest.raises(RuntimeError, match="no se pueden modificar"):
        entry.save()
    with pytest.raises(RuntimeError, match="no se pueden borrar"):
        entry.delete()
