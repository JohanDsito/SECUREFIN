"""Revocación de sesiones (T035; R13; FR-010, FR-012; U3)."""

from __future__ import annotations

from django.db import transaction

from apps.audit.services import record_event


def revoke_all(user, except_current=None, actor=None, reason: str = "revocation") -> int:
    """Borra TODAS las sesiones del usuario, tanto pre_auth como full (U3).

    ``except_current`` es la sesión (SessionStore) de la petición actual que debe conservarse.
    Devuelve el número de sesiones revocadas.
    """
    from apps.iam.models import UserSession

    qs = UserSession.objects.filter(user=user)
    keep = getattr(except_current, "row", None) if except_current is not None else None
    if keep is not None:
        qs = qs.exclude(key_verifier=keep.key_verifier)
    with transaction.atomic():
        counts = {
            "pre_auth": qs.filter(auth_level="pre_auth").count(),
            "full": qs.filter(auth_level="full").count(),
        }
        deleted, _ = qs.delete()
        record_event(
            "sessions_revoked",
            "success",
            actor_id=getattr(actor, "id", None) or user.id,
            target_type="user",
            target_id=user.id,
            metadata={"reason": reason, **counts},
        )
    return deleted


def revoke_one(user, public_id) -> bool:
    """Revoca una sesión concreta del propio usuario (FR-010). Ajena o inexistente → False."""
    from apps.iam.models import UserSession

    deleted, _ = UserSession.objects.filter(user=user, public_id=public_id).delete()
    if deleted:
        record_event(
            "sessions_revoked",
            "success",
            actor_id=user.id,
            target_type="session",
            target_id=public_id,
            metadata={"reason": "user_revoked_session", "pre_auth": 0, "full": deleted},
        )
    return bool(deleted)
