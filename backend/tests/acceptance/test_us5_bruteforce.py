"""TS-A05 (T097): escenarios 1–6 de la Historia de Usuario 5 (protección frente a intentos repetidos).

1. Desde el 5.º fallo consecutivo, cada intento exige un retraso creciente que nunca supera 15 min.
2. Durante el retraso, el intento se rechaza sin evaluar credenciales y con la respuesta genérica.
3. Una autenticación correcta tras el retraso reinicia el contador.
4. Un mismo origen que supera el umbral contra una o varias cuentas queda limitado y se registra
   un evento anómalo.
5. Un identificador inexistente se comporta igual que una cuenta existente.
6. Cuando termina el enfriamiento, la víctima puede volver a autenticarse (sin bloqueo permanente).
"""

from __future__ import annotations

import itertools

import pytest

from apps.audit.models import SecurityEvent
from apps.iam.services import throttling
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.acceptance

WRONG = "contraseña equivocada larga 2026"
_ips = itertools.count(1)


def _client(api_factory):
    """Una IP distinta por intento: así actúa el límite POR CUENTA y no el de IP (T101)."""
    n = next(_ips)
    return api_factory(ip=f"198.19.{n // 250}.{n % 250 + 1}")


def _login(api_factory, email, password=WRONG):
    return _client(api_factory).login(email, password)


def test_us5_1_growing_delay_capped_at_fifteen_minutes(api_factory, make_user, clock):
    user = make_user()
    for _ in range(5):
        assert _login(api_factory, user.email).status_code == 401

    observed = []
    for _ in range(7):
        wait = throttling.check(user.email)
        observed.append(wait)
        assert _login(api_factory, user.email, STRONG_PASSWORD).status_code == 401  # aún en retraso
        clock.advance(seconds=wait)
        assert _login(api_factory, user.email).status_code == 401  # nuevo fallo, retraso mayor
    assert observed == [30, 60, 120, 240, 480, 900, 900]
    assert max(observed) <= 15 * 60


def test_us5_2_attempt_during_delay_is_rejected_generically(api_factory, make_user, clock):
    user = make_user()
    wrong = [_login(api_factory, user.email) for _ in range(5)]
    during_delay = _login(api_factory, user.email, STRONG_PASSWORD)
    assert during_delay.status_code == wrong[0].status_code == 401
    assert during_delay.content == wrong[0].content  # mismo cuerpo: no revela el retraso
    assert "Retry-After" not in during_delay.headers


def test_us5_3_successful_login_after_delay_resets_counter(api_factory, make_user, clock):
    user = make_user()
    for _ in range(6):
        _login(api_factory, user.email)
        clock.advance(seconds=throttling.check(user.email))
    assert _login(api_factory, user.email, STRONG_PASSWORD).status_code == 200
    assert throttling.check(user.email) == 0
    for _ in range(4):
        assert _login(api_factory, user.email).status_code == 401
    assert throttling.check(user.email) == 0  # tras reiniciar, 4 fallos no provocan retraso


def test_us5_4_same_origin_against_many_accounts_is_limited_and_flagged(api_factory, make_user, db):
    attacker = api_factory(ip="203.0.113.66")  # UNA sola IP contra muchas cuentas
    users = [make_user() for _ in range(12)]
    codes = [attacker.login(u.email, WRONG).status_code for u in users]
    codes += [attacker.login(f"x{i}@lab.securefin.local", WRONG).status_code for i in range(10)]

    assert codes[:20] == [401] * 20
    assert 429 in codes[20:]  # límite por IP (login 20/min)
    stuffing = SecurityEvent.objects.get(event_type="credential_stuffing_suspected")
    assert str(stuffing.source_ip) == "203.0.113.66"
    assert SecurityEvent.objects.filter(event_type="throttle_ip_limited", metadata__scope="login").exists()


def test_us5_5_unknown_identifier_same_observable_behaviour(api_factory, make_user, clock):
    existing = make_user()
    seq_existing = [_login(api_factory, existing.email) for _ in range(7)]
    seq_unknown = [_login(api_factory, "fantasma@lab.securefin.local") for _ in range(7)]
    assert [r.status_code for r in seq_existing] == [r.status_code for r in seq_unknown]
    assert [r.content for r in seq_existing] == [r.content for r in seq_unknown]
    assert throttling.check(existing.email) == throttling.check("fantasma@lab.securefin.local") == 30


def test_us5_6_victim_can_log_in_after_cooldown(api_factory, make_user, clock):
    """Un atacante provoca fallos sobre la víctima; al terminar el enfriamiento, la víctima entra.

    No hay bloqueo permanente (FR-038): el peor caso es esperar 15 min. La recuperación de contraseña
    por correo (US7, T113–T115) no depende de este contador y se probará al implementarla.
    """
    victim = make_user()
    for _ in range(12):  # el atacante insiste mucho más allá del umbral
        _login(api_factory, victim.email)
    wait = throttling.check(victim.email)
    assert 0 < wait <= 900
    assert _login(api_factory, victim.email, STRONG_PASSWORD).status_code == 401
    clock.advance(seconds=wait)
    assert _login(api_factory, victim.email, STRONG_PASSWORD).status_code == 200
