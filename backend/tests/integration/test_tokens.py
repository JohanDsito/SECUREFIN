"""TS-I11 (T025): ciclo de vida de los tokens de un solo uso y caducidades separadas."""

import threading
from datetime import timedelta

import pytest
from django.db import connection

from apps.iam.crypto import hmac_verifiers
from apps.iam.models import OneTimeToken
from apps.iam.services import tokens
from apps.iam.services.tokens import InvalidToken

pytestmark = pytest.mark.integration


def test_issue_stores_only_hmac_and_redeems_once(make_user):
    user = make_user()
    token = tokens.issue(user, "password_reset")
    record = OneTimeToken.objects.get()
    assert token not in (record.verifier, record.id)
    assert record.verifier == hmac_verifiers.token_verifier("password_reset", token)[1]
    assert tokens.redeem(token, "password_reset") == user
    with pytest.raises(InvalidToken):
        tokens.redeem(token, "password_reset")


def test_new_token_invalidates_previous(make_user):
    user = make_user()
    first = tokens.issue(user, "password_reset")
    second = tokens.issue(user, "password_reset")
    with pytest.raises(InvalidToken):
        tokens.redeem(first, "password_reset")
    assert tokens.redeem(second, "password_reset") == user


@pytest.mark.parametrize("mutate", [lambda t: t[:-1] + ("A" if t[-1] != "A" else "B"), lambda t: t + "x", lambda t: ""])
def test_altered_tokens_rejected(make_user, mutate):
    token = tokens.issue(make_user(), "account_activation")
    with pytest.raises(InvalidToken):
        tokens.redeem(mutate(token), "account_activation")


def test_purpose_separation(make_user):
    token = tokens.issue(make_user(), "account_activation")
    with pytest.raises(InvalidToken):
        tokens.redeem(token, "password_reset")


@pytest.mark.parametrize(
    "purpose,ok,expired",
    [
        ("account_activation", timedelta(hours=23, minutes=59, seconds=59), timedelta(hours=24, seconds=1)),
        ("password_reset", timedelta(minutes=14, seconds=59), timedelta(minutes=15, seconds=1)),  # FR-046
    ],
)
def test_ttl_boundaries(make_user, clock, purpose, ok, expired):
    user = make_user()
    start = clock.now()
    valid = tokens.issue(user, purpose)
    clock.current = start + ok
    assert tokens.redeem(valid, purpose) == user
    clock.current = start
    late = tokens.issue(user, purpose)
    clock.current = start + expired
    with pytest.raises(InvalidToken):
        tokens.redeem(late, purpose)


# Las pruebas transaccionales vacían la base de datos al terminar. Se excluye la app `audit`: su
# trigger BEFORE TRUNCATE impide (correctamente) vaciar la tabla de eventos.
NON_AUDIT_APPS = ["django.contrib.contenttypes", "django.contrib.auth", "rest_framework", "apps.core", "apps.iam"]


@pytest.mark.django_db(transaction=True, available_apps=NON_AUDIT_APPS)
def test_concurrent_redeem_only_one_succeeds(make_user):
    token = tokens.issue(make_user(), "password_reset")
    results = []
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        try:
            tokens.redeem(token, "password_reset")
            results.append("ok")
        except InvalidToken:
            results.append("invalid")
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["invalid", "ok"]
