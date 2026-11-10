"""Eventos de seguridad append-only frente a la aplicación (T036; R14; data-model → SecurityEvent).

Tres capas de protección: este modelo (bloquea modificar y borrar), triggers de PostgreSQL y el rol
`securefin_app` sin UPDATE/DELETE/TRUNCATE. No hay inmutabilidad absoluta: el superusuario
`postgres` y `securefin_owner` pueden saltarse los controles (riesgo residual T-36).
"""

from __future__ import annotations

import uuid

from django.db import models

from apps.core import clock

EVENT_TYPES = [
    # Cuenta
    "account_registered", "account_activated", "activation_sent", "account_created_by_admin",
    "account_deactivated", "account_reactivated", "role_changed",
    # Autenticación
    "login_succeeded", "login_failed", "logout", "session_expired", "sessions_revoked",
    # MFA
    "mfa_enabled", "mfa_disabled", "mfa_reconfigured", "totp_rejected", "recovery_code_used",
    "recovery_codes_regenerated",
    # Reinicio de MFA
    "mfa_reset_requested", "mfa_reset_case_opened", "mfa_reset_authorized", "mfa_reset_cancelled",
    # Recuperación
    "password_reset_requested", "password_reset_completed", "password_changed",
    "email_delivery_failed",
    # Limitación
    "throttle_account_delay", "throttle_ip_limited", "credential_stuffing_suspected",
    # Autorización
    "authz_denied",
    # Operaciones financieras ficticias
    "finance_account_opened", "finance_account_welcome_credited", "finance_transfer_created",
    "finance_transfer_completed", "finance_transfer_rejected", "finance_approval_decided",
    "finance_limit_changed", "finance_risk_alert", "finance_card_created",
    "finance_card_status_changed",
    # Consola
    "bootstrap_admin_executed", "break_glass_executed",
]
assert len(EVENT_TYPES) == len(set(EVENT_TYPES)) == 42, "El catálogo de eventos debe ser único"


class Outcome(models.TextChoices):
    SUCCESS = "success", "Éxito"
    FAILURE = "failure", "Fallo"
    DENIED = "denied", "Denegado"


class ImmutableEventError(RuntimeError):
    pass


class SecurityEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(default=clock.default_now, db_index=True)
    event_type = models.CharField(
        max_length=40, choices=[(e, e) for e in EVENT_TYPES], db_index=True
    )
    outcome = models.CharField(max_length=10, choices=Outcome.choices)
    actor_id = models.UUIDField(null=True)
    actor_role = models.CharField(max_length=10, null=True)
    target_type = models.CharField(max_length=40, null=True)
    target_id = models.UUIDField(null=True)
    source_ip = models.GenericIPAddressField(null=True)
    request_id = models.UUIDField()
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = "audit_securityevent"
        ordering = ["-occurred_at"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ImmutableEventError("Los eventos de seguridad no se pueden modificar.")
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ImmutableEventError("Los eventos de seguridad no se pueden borrar.")
