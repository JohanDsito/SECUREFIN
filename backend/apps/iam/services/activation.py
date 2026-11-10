"""Activación de cuentas privilegiadas mediante token de un solo uso (T087; FR-021).

- Handler del outbox para 'account_activation': genera token HMAC efímero (24 h)
  y compone correo con fragmento https://securefin.local/activate#token=...
- Tras la entrega SMTP correcta, registra el evento 'activation_sent' sin datos sensibles.
- `activate(token, password)`: canjea token (un solo uso), valida contraseña con política
  Argon2id, activa la cuenta y registra 'account_activated'.
"""

from __future__ import annotations

from django.contrib.auth.password_validation import validate_password
from django.db import transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.models import OutboxKind, OutboxMessage, Status, TokenPurpose, User
from apps.iam.policies.password_validators import normalize_password
from apps.iam.services import outbox, tokens


def handle_account_activation(message: OutboxMessage) -> outbox.ComposedEmail:
    """Compone el correo de activación generando el token en memoria en el momento del envío."""
    token = tokens.issue(message.user, TokenPurpose.ACCOUNT_ACTIVATION)
    link = f"https://securefin.local/activate#token={token}"

    def on_sent() -> None:
        record_event(
            "activation_sent",
            "success",
            target_type="user",
            target_id=message.user_id,
        )

    body = (
        f"Hola {message.user.name},\n\n"
        f"Tu cuenta ha sido creada en SecureFin Gateway.\n"
        f"Para activarla y establecer tu contraseña, accede al siguiente enlace:\n\n"
        f"{link}\n\n"
        f"Este enlace caduca en 24 horas y solo puede utilizarse una vez.\n"
    )
    return outbox.ComposedEmail(
        subject="Activa tu cuenta en SecureFin Gateway",
        body=body,
        on_sent=on_sent,
    )


# Registrar el handler en el outbox
outbox.register_handler(OutboxKind.ACCOUNT_ACTIVATION, handle_account_activation)


def activate(token: str, password: str, source_ip: str | None = None) -> User:
    """Canjea el token de activación, establece la contraseña y pasa la cuenta a active.

    Todo ocurre en una única transacción: si la contraseña incumple la política
    (``django.core.exceptions.ValidationError``), el canje se revierte y el enlace sigue sirviendo
    para un segundo intento. Cualquier problema del token, o una cuenta que ya no está pendiente,
    lanza ``tokens.InvalidToken`` (mismo error para usado, caducado, sustituido o alterado).
    """
    norm_password = normalize_password(password)
    with transaction.atomic():
        user = tokens.redeem(token, TokenPurpose.ACCOUNT_ACTIVATION)
        user = User.objects.select_for_update().get(pk=user.pk)
        if user.status != Status.PENDING_ACTIVATION:
            raise tokens.InvalidToken
        validate_password(norm_password, user=user)

        user.set_password(norm_password)
        user.status = Status.ACTIVE
        user.password_changed_at = clock.now()
        user.save(update_fields=["password", "status", "password_changed_at"])

        record_event(
            "account_activated",
            "success",
            actor=user,
            target_type="user",
            target_id=user.id,
            source_ip=source_ip,
        )

    return user

