"""TS-I18 / TS-I12 / TS-I13 (T026): outbox sin secretos, reintentos y entrega solo al buzón."""

from datetime import timedelta
from unittest import mock

import pytest
from django.core import mail

from apps.audit.models import SecurityEvent
from apps.iam.models import OutboxMessage, OutboxStatus
from apps.iam.services import outbox

pytestmark = pytest.mark.integration


@pytest.fixture
def test_handler():
    secrets_seen = []

    def handler(message):
        secret = "SECRETO-GENERADO-EN-MEMORIA-123"
        secrets_seen.append(secret)
        return outbox.ComposedEmail(subject="Prueba", body=f"Tu enlace: https://securefin.local/reset#token={secret}")

    outbox.register_handler("password_reset", handler)
    yield secrets_seen
    outbox._HANDLERS.pop("password_reset", None)


def test_outbox_model_has_no_secret_fields():
    names = {f.name for f in OutboxMessage._meta.get_fields()}
    assert not names & {"token", "code", "body", "subject", "secret", "verifier"}


def test_delivery_generates_secret_at_send_time_and_never_persists_it(make_user, test_handler):
    user = make_user()
    outbox.enqueue("password_reset", user)
    assert outbox.deliver_due() == {"sent": 1, "retry": 0, "failed": 0}
    assert len(mail.outbox) == 1 and mail.outbox[0].to == [user.email]
    secret = test_handler[0]
    message = OutboxMessage.objects.get()
    assert message.status == OutboxStatus.SENT
    for value in (str(v) for v in message.__dict__.values()):
        assert secret not in value


def test_smtp_down_retries_then_fails_with_event(make_user, test_handler, clock):
    user = make_user()
    outbox.enqueue("password_reset", user)
    with mock.patch("django.core.mail.EmailMessage.send", side_effect=ConnectionRefusedError):
        for attempt in range(1, 6):
            outbox.deliver_due()
            message = OutboxMessage.objects.get()
            assert message.attempts == attempt
            clock.advance(minutes=11)
    assert message.status == OutboxStatus.FAILED
    event = SecurityEvent.objects.get(event_type="email_delivery_failed")
    assert event.metadata == {"kind": "password_reset", "attempts": 5}
    assert "SECRETO" not in str(event.metadata)


def test_not_due_messages_wait(make_user, test_handler, clock):
    user = make_user()
    msg = outbox.enqueue("password_reset", user)
    OutboxMessage.objects.filter(pk=msg.pk).update(next_attempt_at=clock.now() + timedelta(minutes=5))
    assert outbox.deliver_due() == {"sent": 0, "retry": 0, "failed": 0}


def test_missing_handler_is_a_delivery_failure(make_user):
    outbox.enqueue("mfa_reset_notice", make_user())
    stats = outbox.deliver_due()
    assert stats["retry"] == 1 and len(mail.outbox) == 0
