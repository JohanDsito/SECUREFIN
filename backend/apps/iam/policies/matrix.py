"""Matriz de permisos de spec.md como fuente única (T039; R15; FR-013 a FR-016, FR-025)."""

from __future__ import annotations

from apps.iam.models import Role

# Permisos de función
PROFILE_SELF = "profile.self"
SESSIONS_SELF = "sessions.self"
MFA_SELF = "mfa.self"
MFA_DISABLE_SELF = "mfa.disable_self"
RECOVERY_CODES_SELF = "recovery_codes.self"
USERS_LIST = "admin.users.list"
USERS_CREATE_PRIVILEGED = "admin.users.create_privileged"
USERS_MANAGE = "admin.users.manage"
MFA_RESET_OTHERS = "admin.mfa_reset"
AUDIT_READ = "audit.read"
FINANCE_ACCOUNTS_SELF = "finance.accounts.self"
FINANCE_TRANSFERS_CREATE = "finance.transfers.create"
FINANCE_CARDS_SELF = "finance.cards.self"
FINANCE_RISK_READ = "finance.risk.read"
FINANCE_APPROVALS_DECIDE = "finance.approvals.decide"
FINANCE_LIMITS_MANAGE = "finance.limits.manage"
FINANCE_TRANSACTIONS_READ = "finance.transactions.read"
FINANCE_ADMIN_READ = "finance.admin.read"

_SELF_SERVICE = {PROFILE_SELF, SESSIONS_SELF, MFA_SELF, RECOVERY_CODES_SELF}
_FINANCE_SELF_SERVICE = {
    FINANCE_ACCOUNTS_SELF,
    FINANCE_TRANSFERS_CREATE,
    FINANCE_CARDS_SELF,
    FINANCE_TRANSACTIONS_READ,
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.CLIENT: frozenset(_SELF_SERVICE | _FINANCE_SELF_SERVICE | {MFA_DISABLE_SELF}),
    Role.ADMIN: frozenset(
        _SELF_SERVICE
        | {
            USERS_LIST,
            USERS_CREATE_PRIVILEGED,
            USERS_MANAGE,
            MFA_RESET_OTHERS,
            FINANCE_RISK_READ,
            FINANCE_APPROVALS_DECIDE,
            FINANCE_LIMITS_MANAGE,
            FINANCE_ADMIN_READ,
        }
    ),
    Role.AUDITOR: frozenset(
        _SELF_SERVICE | {AUDIT_READ, FINANCE_RISK_READ, FINANCE_TRANSACTIONS_READ, FINANCE_ADMIN_READ}
    ),
}

# Requisito de MFA como atributo del rol: cualquier rol nuevo es obligatorio por defecto (FR-025).
ROLE_MFA_REQUIRED: dict[str, bool] = {Role.CLIENT: False, Role.ADMIN: True, Role.AUDITOR: True}


def mfa_required(role: str) -> bool:
    return ROLE_MFA_REQUIRED.get(role, True)


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())  # denegar por defecto
