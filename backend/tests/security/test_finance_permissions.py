import pytest

from apps.iam.models import Role
from apps.iam.policies.matrix import (
    FINANCE_ACCOUNTS_SELF,
    FINANCE_APPROVALS_DECIDE,
    FINANCE_LIMITS_MANAGE,
    FINANCE_RISK_READ,
    FINANCE_TRANSFERS_CREATE,
    has_permission,
)


@pytest.mark.unit
def test_finance_permission_matrix_separates_client_admin_and_auditor():
    assert has_permission(Role.CLIENT, FINANCE_ACCOUNTS_SELF)
    assert has_permission(Role.CLIENT, FINANCE_TRANSFERS_CREATE)
    assert not has_permission(Role.CLIENT, FINANCE_APPROVALS_DECIDE)
    assert not has_permission(Role.CLIENT, FINANCE_LIMITS_MANAGE)

    assert has_permission(Role.ADMIN, FINANCE_APPROVALS_DECIDE)
    assert has_permission(Role.ADMIN, FINANCE_LIMITS_MANAGE)
    assert has_permission(Role.ADMIN, FINANCE_RISK_READ)

    assert has_permission(Role.AUDITOR, FINANCE_RISK_READ)
    assert not has_permission(Role.AUDITOR, FINANCE_APPROVALS_DECIDE)
    assert not has_permission(Role.AUDITOR, FINANCE_LIMITS_MANAGE)
