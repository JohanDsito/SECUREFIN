"""TS-S27 (T131): el login no permite enumerar cuentas (NFR-003; corrección G1).

Compara usuarios existentes con contraseña errónea frente a usuarios inexistentes: mismo estado,
mismo cuerpo, mismo conjunto de cabeceras y diferencia media de tiempo < 100 ms. El número de
muestras por grupo es 200 (configurable con SECUREFIN_TIMING_SAMPLES).
"""

import os
import statistics
import time
from unittest import mock

import pytest

from apps.iam.services import authentication

pytestmark = pytest.mark.security

SAMPLES = int(os.environ.get("SECUREFIN_TIMING_SAMPLES", "200"))
WRONG = "contraseña incorrecta pero larga"


def _measure(api_factory, emails):
    timings, responses = [], []
    for email in emails:
        client = api_factory()
        client.fetch_csrf()
        start = time.perf_counter()
        response = client.login(email, WRONG)
        timings.append(time.perf_counter() - start)
        responses.append(response)
    return timings, responses


def test_s27_login_enumeration_resistance(api_factory, make_user):
    existing = [make_user().email for _ in range(SAMPLES)]
    unknown = [f"inexistente{i}@lab.securefin.local" for i in range(SAMPLES)]
    t_exist, r_exist = _measure(api_factory, existing)
    t_unknown, r_unknown = _measure(api_factory, unknown)

    for a, b in zip(r_exist, r_unknown):
        assert a.status_code == b.status_code == 401
        assert a.content == b.content
        assert set(a.headers) - {"Date", "X-Request-ID"} == set(b.headers) - {"Date", "X-Request-ID"}
        assert "__Host-sf_session" not in a.cookies and "__Host-sf_session" not in b.cookies

    delta = abs(statistics.mean(t_exist) - statistics.mean(t_unknown))
    report = (
        f"existentes media={statistics.mean(t_exist):.4f}s mediana={statistics.median(t_exist):.4f}s "
        f"p95={sorted(t_exist)[int(0.95 * len(t_exist)) - 1]:.4f}s | inexistentes media={statistics.mean(t_unknown):.4f}s "
        f"mediana={statistics.median(t_unknown):.4f}s p95={sorted(t_unknown)[int(0.95 * len(t_unknown)) - 1]:.4f}s | "
        f"delta media={delta * 1000:.1f} ms"
    )
    print(report)
    assert delta < 0.100, report


def test_s27_unknown_path_runs_dummy_hash(api, db):
    with mock.patch.object(authentication, "check_password", wraps=authentication.check_password) as spy:
        api.login("inexistente@lab.securefin.local", WRONG)
    spy.assert_called_once()
