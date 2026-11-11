"""Outbox de correo sin secretos y su entrega controlada (T044; R9).

La petición solo encola (``enqueue``). El proceso ``mailer`` (``iam_deliver_outbox``) genera el
token o código en el momento de la entrega, compone el correo en memoria y lo envía al buzón de
laboratorio. Cada historia registra el *handler* de su tipo de mensaje con ``register_handler``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from django.core.mail import EmailMessage
from django.db import transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.models import OutboxMessage, OutboxStatus
from apps.iam.models.outbox import MAX_ATTEMPTS

logger = logging.getLogger("securefin.outbox")


@dataclass
class ComposedEmail:
    subject: str
    body: str
    on_sent: Callable[[], None] | None = None


Handler = Callable[[OutboxMessage], ComposedEmail]
_HANDLERS: dict[str, Handler] = {}


def register_handler(kind: str, handler: Handler) -> None:
    _HANDLERS[kind] = handler


def enqueue(kind: str, user, related_id=None) -> OutboxMessage:
    return OutboxMessage.objects.create(kind=kind, user=user, related_id=related_id)


def _backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(30 * 2 ** (attempts - 1), 600))  # 30 s, 60 s, 120 s, 240 s…


def deliver_due(limit: int = 20) -> dict[str, int]:
    """Entrega los mensajes vencidos. Nunca registra tokens, códigos ni cuerpos."""
    stats = {"sent": 0, "retry": 0, "failed": 0}
    now = clock.now()
    with transaction.atomic():
        batch = list(
            OutboxMessage.objects.select_for_update(skip_locked=True)
            .select_related("user")
            .filter(status=OutboxStatus.PENDING, next_attempt_at__lte=now)
            .order_by("created_at")[:limit]
        )
        for message in batch:
            message.status = OutboxStatus.SENDING
            message.save(update_fields=["status"])
    for message in batch:
        _deliver_one(message, stats)
    return stats


def _deliver_one(message: OutboxMessage, stats: dict[str, int]) -> None:
    handler = _HANDLERS.get(message.kind)
    message.attempts += 1
    try:
        if handler is None:
            raise LookupError(f"Sin handler para {message.kind}")
        composed = handler(message)  # genera el secreto en memoria
        EmailMessage(composed.subject, composed.body, to=[message.user.email]).send(fail_silently=False)
        if composed.on_sent is not None:
            composed.on_sent()
    except Exception as exc:  # noqa: BLE001 - cualquier fallo de entrega se reintenta
        logger.warning("Fallo de entrega del outbox kind=%s attempts=%s error=%s", message.kind, message.attempts, type(exc).__name__)
        if message.attempts >= MAX_ATTEMPTS:
            message.status = OutboxStatus.FAILED
            stats["failed"] += 1
            record_event(
                "email_delivery_failed",
                "failure",
                target_type="user",
                target_id=message.user_id,
                metadata={"kind": message.kind, "attempts": message.attempts},
            )
        else:
            message.status = OutboxStatus.PENDING
            message.next_attempt_at = clock.now() + _backoff(message.attempts)
            stats["retry"] += 1
        message.save(update_fields=["status", "attempts", "next_attempt_at"])
        return
    message.status = OutboxStatus.SENT
    message.sent_at = clock.now()
    message.save(update_fields=["status", "attempts", "sent_at"])
    stats["sent"] += 1
