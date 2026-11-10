"""TS-S28 (T132): limitación por IP, parametrizada por ámbito (FR-037; R12; T101).

Para cada ámbito, desde una IP simulada (`X-Forwarded-For`, `NUM_PROXIES = 1`) y con identificadores
distintos en cada petición (para no depender de la limitación por cuenta):
- las N primeras peticiones no devuelven 429;
- la N+1 devuelve 429 con `Retry-After` (entero positivo);
- se registra `throttle_ip_limited` con `metadata.scope` y la IP en `source_ip`;
- otra IP no queda afectada;
- el contador se reinicia al pasar la ventana (reloj simulado).
El ámbito `recovery` lo prueba T137 cuando exista su ruta (US7).
"""

from __future__ import annotations

import itertools

import pytest

from apps.audit.models import SecurityEvent
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.security

_n = itertools.count(1)


def _login(c):
    return c.post("/auth/login", {"email": f"ip-login-{next(_n)}@lab.securefin.local", "password": "incorrecta 1234567"})


def _mfa(c):
    return c.post("/auth/login/mfa", {"totp_code": "000000"})


def _register(c):
    n = next(_n)
    return c.post("/auth/register", {"email": f"ip-reg-{n}@lab.securefin.local", "name": f"R{n}", "password": STRONG_PASSWORD})


def _activate(c):
    return c.post("/auth/activate", {"token": f"token-invalido-{next(_n)}", "password": STRONG_PASSWORD})


def _mfa_reset_request(c):
    return c.post("/auth/login/mfa-reset-request", {})


# (ámbito, petición, umbral N, ventana en segundos)
SCOPES = [
    ("login", _login, 20, 60),
    ("mfa", _mfa, 10, 60),
    ("register", _register, 5, 3600),
    ("activation", _activate, 10, 3600),
    ("mfa_reset_request", _mfa_reset_request, 3, 86400),
]


@pytest.mark.parametrize(("scope", "request_fn", "limit", "window"), SCOPES, ids=[s[0] for s in SCOPES])
def test_ip_rate_limit_per_scope(api_factory, db, clock, scope, request_fn, limit, window):
    ip = "198.51.100.77"
    client = api_factory(ip=ip)

    for i in range(limit):
        assert request_fn(client).status_code != 429, f"{scope}: petición {i + 1} limitada antes de tiempo"

    blocked = request_fn(client)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "throttled"
    assert int(blocked.headers["Retry-After"]) > 0

    event = SecurityEvent.objects.filter(event_type="throttle_ip_limited", metadata__scope=scope).latest("occurred_at")
    assert str(event.source_ip) == ip
    assert set(event.metadata) == {"scope"}  # nada sensible en los metadatos

    # Otra IP no queda afectada
    assert request_fn(api_factory(ip="198.51.100.78")).status_code != 429

    # Al pasar la ventana, el contador de la primera IP se reinicia
    clock.advance(seconds=window + 1)
    assert request_fn(client).status_code != 429


def test_scopes_do_not_share_counters(api_factory, db):
    """Agotar `mfa_reset_request` (3/día) no afecta al login desde la misma IP."""
    client = api_factory(ip="198.51.100.90")
    for _ in range(4):
        _mfa_reset_request(client)
    assert _mfa_reset_request(client).status_code == 429
    assert _login(client).status_code == 401


def test_csrf_and_session_routes_are_not_throttled(api_factory, db):
    client = api_factory(ip="198.51.100.91")
    for _ in range(30):
        assert client.fetch_csrf().status_code == 204
