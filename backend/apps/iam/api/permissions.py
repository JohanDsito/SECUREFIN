"""Permisos DRF: denegar por defecto, RBAC de función y de objeto (T040; R15)."""

from __future__ import annotations

from rest_framework.exceptions import NotFound
from rest_framework.permissions import BasePermission

from apps.audit.services import record_event
from apps.iam.policies.matrix import has_permission, mfa_required
from apps.iam.services.mfa_state import user_mfa_enabled
from apps.iam.sessions import keys as K
from apps.iam.sessions.middleware import client_ip


class IsFullyAuthenticated(BasePermission):
    """Sesión `full`, usuario activo y MFA cumplido según el rol. Permiso por defecto global."""

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        session = getattr(request, "session", None)
        if session is None or session.get(K.LEVEL) != K.FULL:
            return False
        if not user.is_active:
            return False
        if mfa_required(user.role) and not user_mfa_enabled(user):
            return False
        return True


def HasRolePermission(permission: str):  # noqa: N802 - factoría de clases de permiso
    class _HasRolePermission(BasePermission):
        def has_permission(self, request, view):
            user = request.user
            allowed = bool(user and user.is_authenticated and has_permission(user.role, permission))
            if not allowed and user and user.is_authenticated:
                record_event(
                    "authz_denied",
                    "denied",
                    actor=user,
                    source_ip=client_ip(request),
                    metadata={"path": request.path[:200], "method": request.method, "reason": "function"},
                )
            return allowed

    _HasRolePermission.__name__ = f"HasRolePermission[{permission}]"
    return _HasRolePermission


def resolve_owned_user(request, user_id: str):
    """Autorización a nivel de objeto: solo el propio usuario (alias `me`). Ajeno o inexistente → 404."""
    user = request.user
    if user_id == "me" or str(user.id) == str(user_id):
        return user
    record_event(
        "authz_denied",
        "denied",
        actor=user,
        source_ip=client_ip(request),
        metadata={"path": request.path[:200], "method": request.method, "reason": "object"},
    )
    raise NotFound()
