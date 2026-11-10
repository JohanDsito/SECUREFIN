"""TS-S13 / TS-S14 (T096): fuerza bruta contra una cuenta (FR-036, FR-038).

- En 100 intentos rápidos, como máximo 5 llegan a evaluar la contraseña antes del primer retraso.
- Durante el retraso los intentos se rechazan SIN invocar el hasher (se cuenta con un mock que
  envuelve al hasher real).
- Mismo comportamiento observable para un identificador inexistente.
- Los fallos de TOTP y de código de recuperación cuentan para el mismo contador.

Cada intento sale de una IP distinta: así se prueba la limitación POR CUENTA, sin que la tape la
limitación por IP de T101 (tests/security/test_ip_rate_limits.py).
"""

from __future__ import annotations

import itertools
from unittest import mock

import pytest

from apps.iam.policies.hashers import SecureFinArgon2Hasher
from apps.iam.services import recovery_codes
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.security

WRONG = "contraseña equivocada larga 2026"
_ips = itertools.count(1)


def _client(api_factory):
    n = next(_ips)
    return api_factory(ip=f"198.18.{n // 250}.{n % 250 + 1}")


@pytest.fixture
def hasher_calls():
    """Cuenta las verificaciones Argon2id reales (incluida la del hash ficticio)."""
    original = SecureFinArgon2Hasher.verify
    with mock.patch.object(SecureFinArgon2Hasher, "verify", autospec=True, side_effect=original) as spy:
        yield spy


def test_at_most_five_evaluated_in_100_rapid_attempts(api_factory, make_user, clock, hasher_calls):
    user = make_user()
    codes = [_client(api_factory).login(user.email, WRONG).status_code for _ in range(100)]
    assert set(codes) == {401}
    assert hasher_calls.call_count <= 5


def test_attempts_during_delay_skip_the_hasher_even_with_the_right_password(api_factory, make_user, clock, hasher_calls):
    user = make_user()
    for _ in range(5):
        _client(api_factory).login(user.email, WRONG)
    before = hasher_calls.call_count

    resp = _client(api_factory).login(user.email, STRONG_PASSWORD)  # contraseña CORRECTA
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "auth_failed"
    assert hasher_calls.call_count == before  # no se evaluó

    clock.advance(seconds=30)
    assert _client(api_factory).login(user.email, STRONG_PASSWORD).status_code == 200


def test_unknown_identifier_behaves_like_existing_account(api_factory, make_user, clock, hasher_calls):
    existing = make_user()
    observed = {}
    for email in (existing.email, "nadie-existe@lab.securefin.local"):
        start = hasher_calls.call_count
        responses = [_client(api_factory).login(email, WRONG) for _ in range(8)]
        observed[email] = (
            [r.status_code for r in responses],
            [r.content for r in responses],
            hasher_calls.call_count - start,
        )
    a, b = observed.values()
    assert a == b
    assert a[2] == 5  # en los dos casos: 5 evaluaciones, las 3 siguientes rechazadas sin hasher


def test_totp_and_recovery_code_failures_count(api_factory, make_user, clock):
    user = make_user(role="client")
    secret = make_totp_device(user)
    recovery_codes.generate_batch(user)

    pre = _client(api_factory)
    assert pre.login(user.email).json() == {"status": "mfa_required"}  # contraseña correcta
    for _ in range(3):
        assert pre.post("/auth/login/mfa", {"totp_code": "000000"}).status_code == 401
    for _ in range(2):
        assert pre.post("/auth/login/mfa", {"recovery_code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG"}).status_code == 401

    # 5 fallos de segundo factor: incluso el TOTP correcto se rechaza ahora
    assert pre.post("/auth/login/mfa", {"totp_code": totp_code(secret)}).status_code == 401
    # y también la contraseña correcta en un login nuevo
    assert _client(api_factory).login(user.email).status_code == 401


def test_correct_password_does_not_reset_counter_for_mfa_users(api_factory, make_user, clock):
    """Quien conoce la contraseña no puede alternar 'contraseña correcta → TOTP al azar' sin fin."""
    user = make_user(role="client")
    make_totp_device(user)
    for _ in range(5):
        c = _client(api_factory)
        assert c.login(user.email).json() == {"status": "mfa_required"}
        assert c.post("/auth/login/mfa", {"totp_code": "000000"}).status_code == 401
    assert _client(api_factory).login(user.email).status_code == 401  # en retraso


def test_full_authentication_resets_counter(api_factory, make_user, clock):
    user = make_user(role="client")
    secret = make_totp_device(user)
    for _ in range(4):
        _client(api_factory).login(user.email, WRONG)

    c = _client(api_factory)
    assert c.login(user.email).json() == {"status": "mfa_required"}
    assert c.post("/auth/login/mfa", {"totp_code": totp_code(secret)}).status_code == 200

    for _ in range(4):  # tras el éxito, 4 fallos nuevos no provocan retraso
        assert _client(api_factory).login(user.email, WRONG).status_code == 401
    assert _client(api_factory).login(user.email).status_code == 200
