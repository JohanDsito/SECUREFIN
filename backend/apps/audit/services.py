"""Registro de eventos de seguridad (T037; FR-040 a FR-044; Principio VI).

- Solo tipos del catálogo cerrado.
- ``metadata`` limitada a claves permitidas por tipo; las claves sensibles se rechazan siempre.
- Se ejecuta dentro de la transacción del llamador: si falla, la operación administrativa se
  revierte (fallo cerrado, FR-044).
"""

from __future__ import annotations

import uuid
from typing import Any

from apps.audit.models import EVENT_TYPES, SecurityEvent
from apps.core.middleware import current_request_id

FORBIDDEN_KEY_PARTS = ("password", "token", "secret", "code", "otp", "session_key", "cookie", "hash")

_COMMON = {"reason", "auth_level", "scope", "role", "channel", "count", "pre_auth", "full"}
METADATA_ALLOWLIST: dict[str, set[str]] = {
    "login_failed": {"reason", "stage"},
    "login_succeeded": {"auth_level", "mfa_method"},
    "session_expired": {"reason", "auth_level"},
    "sessions_revoked": {"reason", "pre_auth", "full"},
    "role_changed": {"from_role", "to_role"},
    "account_created_by_admin": {"role"},
    "authz_denied": {"path", "method", "reason"},
    "throttle_account_delay": {"delay_seconds", "failures"},
    "throttle_ip_limited": {"scope"},
    "credential_stuffing_suspected": {"distinct_identifiers", "window_minutes"},
    "recovery_code_used": {"remaining"},
    "mfa_reset_authorized": {"verification_method", "requested_at", "opened_at"},
    "mfa_reset_case_opened": {"channel"},
    "email_delivery_failed": {"kind", "attempts"},
    "break_glass_executed": {"os_user", "reason"},
    "bootstrap_admin_executed": {"os_user"},
}


class AuditError(ValueError):
    pass


def _check_metadata(event_type: str, metadata: dict[str, Any]) -> dict[str, Any]:
    allowed = METADATA_ALLOWLIST.get(event_type, set()) | _COMMON
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        lowered = key.lower()
        if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
            raise AuditError(f"Clave prohibida en metadata de auditoría: {key}")
        if key not in allowed:
            raise AuditError(f"Clave no permitida para {event_type}: {key}")
        if isinstance(value, (uuid.UUID,)):
            value = str(value)
        clean[key] = value
    return clean


def record_event(
    event_type: str,
    outcome: str,
    *,
    actor=None,
    actor_id=None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id=None,
    source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    if event_type not in EVENT_TYPES:
        raise AuditError(f"Tipo de evento desconocido: {event_type}")
    if actor is not None:
        actor_id = actor_id or getattr(actor, "id", None)
        actor_role = actor_role or getattr(actor, "role", None)
    event = SecurityEvent(
        event_type=event_type,
        outcome=outcome,
        actor_id=actor_id,
        actor_role=actor_role,
        target_type=target_type,
        target_id=target_id,
        source_ip=source_ip,
        request_id=current_request_id(),
        metadata=_check_metadata(event_type, metadata or {}),
    )
    event.save()
    return event
