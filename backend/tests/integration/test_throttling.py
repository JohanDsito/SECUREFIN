"""TS-I15 / TS-I16 (T095): limitación progresiva por cuenta, con reloj simulado (R12; FR-036–FR-039).

- Desde el 5.º fallo consecutivo: retrasos de 30, 60, 120, 240, 480 y 900 s; 900 s es el tope.
- El contador se reinicia tras un éxito y tras 30 min sin fallos.
- Eventos: `throttle_account_delay` (cada retraso), `credential_stuffing_suspected` (10 o más
  identificadores distintos con fallos en 15 min desde una IP). `throttle_ip_limited` lo prueba TS-S28
  (`tests/security/test_ip_rate_limits.py`).
- El resumen del identificador es un HMAC con THROTTLE_HMAC_KEYS: nunca se guarda el correo.
- Rotación: `check` consulta todas las versiones aceptadas y los fallos nuevos heredan el contador.
"""

from __future__ import annotations

from unittest import mock

import pytest

from apps.audit.models import SecurityEvent
from apps.core.keys import KeySet, get_keyset
from apps.iam.models import AuthThrottle
from apps.iam.services import throttling

pytestmark = pytest.mark.integration

EMAIL = "victima@lab.securefin.local"
IP = "198.51.100.20"


def _fail(n: int, email: str = EMAIL, ip: str = IP) -> list[int]:
    return [throttling.register_failure(email, ip) for _ in range(n)]


def test_no_delay_before_fifth_failure(db, clock):
    assert _fail(4) == [0, 0, 0, 0]
    assert throttling.check(EMAIL) == 0


def test_delay_sequence_and_cap(db, clock):
    delays = []
    for _ in range(11):
        while (wait := throttling.check(EMAIL)) > 0:  # respeta el retraso, como un cliente paciente
            clock.advance(seconds=wait)
        delays.append(throttling.register_failure(EMAIL, IP))
    assert delays == [0, 0, 0, 0, 30, 60, 120, 240, 480, 900, 900]


def test_check_reports_remaining_seconds(db, clock):
    _fail(5)
    assert throttling.check(EMAIL) == 30
    clock.advance(seconds=12)
    assert throttling.check(EMAIL) == 18
    clock.advance(seconds=18)
    assert throttling.check(EMAIL) == 0


def test_identifier_is_normalized(db, clock):
    _fail(5, email="  Victima@LAB.securefin.local ")
    assert throttling.check(EMAIL) == 30


def test_success_resets_counter(db, clock):
    _fail(7)
    throttling.register_success(EMAIL)
    assert throttling.check(EMAIL) == 0
    assert _fail(4) == [0, 0, 0, 0]  # empieza de cero


def test_thirty_minutes_without_failures_resets_counter(db, clock):
    _fail(4)
    clock.advance(minutes=30, seconds=1)
    assert _fail(4) == [0, 0, 0, 0]  # los 4 anteriores ya no cuentan


def test_failures_within_thirty_minutes_accumulate(db, clock):
    _fail(4)
    clock.advance(minutes=29)
    assert throttling.register_failure(EMAIL, IP) == 30


def test_accounts_are_independent(db, clock):
    _fail(5)
    assert throttling.check("otra@lab.securefin.local") == 0


def test_digest_only_no_plain_identifier(db, clock):
    _fail(1)
    row = AuthThrottle.objects.get()
    assert row.scope == "account"
    assert len(row.key_digest) == 64 and EMAIL not in row.key_digest
    assert row.key_version == get_keyset("THROTTLE_HMAC_KEYS").active_version


def test_account_delay_event(db, clock):
    _fail(5)
    event = SecurityEvent.objects.get(event_type="throttle_account_delay")
    assert event.outcome == "denied"
    assert event.metadata == {"delay_seconds": 30, "failures": 5}
    assert str(event.source_ip) == IP
    assert EMAIL not in str(event.metadata)


def test_credential_stuffing_detected_at_ten_distinct_identifiers(db, clock):
    for i in range(9):
        throttling.register_failure(f"u{i}@lab.securefin.local", IP)
    assert not SecurityEvent.objects.filter(event_type="credential_stuffing_suspected").exists()

    throttling.register_failure("u9@lab.securefin.local", IP)
    event = SecurityEvent.objects.get(event_type="credential_stuffing_suspected")
    assert event.metadata == {"distinct_identifiers": 10, "window_minutes": 15}
    assert str(event.source_ip) == IP

    throttling.register_failure("u10@lab.securefin.local", IP)  # una sola alerta por ventana
    assert SecurityEvent.objects.filter(event_type="credential_stuffing_suspected").count() == 1


def test_credential_stuffing_ignores_repeats_other_ips_and_old_failures(db, clock):
    for _ in range(12):
        throttling.register_failure(EMAIL, IP)  # el mismo identificador no cuenta como distinto
    for i in range(5):
        throttling.register_failure(f"a{i}@lab.securefin.local", IP)
    clock.advance(minutes=16)
    for i in range(5):
        throttling.register_failure(f"b{i}@lab.securefin.local", IP)
    for i in range(9):
        throttling.register_failure(f"c{i}@lab.securefin.local", "198.51.100.99")
    assert not SecurityEvent.objects.filter(event_type="credential_stuffing_suspected").exists()


def test_key_rotation_checks_all_versions_and_inherits_counter(db, clock):
    """Durante una rotación (v2 activa, v1 aceptada) no se pierde un retraso vigente."""
    _fail(5)  # retraso registrado con la clave v1
    old = get_keyset("THROTTLE_HMAC_KEYS")
    rotated = KeySet(name=old.name, active_version="v2", keys={"v2": b"k" * 32, "v1": old.get(old.active_version)})

    with mock.patch("apps.iam.crypto.hmac_verifiers.get_keyset", return_value=rotated):
        assert throttling.check(EMAIL) == 30  # el retraso de la fila v1 sigue vigente
        clock.advance(seconds=30)
        assert throttling.register_failure(EMAIL, IP) == 60  # 6.º fallo: hereda el contador
        rows = list(AuthThrottle.objects.values_list("key_version", "consecutive_failures"))
    assert rows == [("v2", 6)]  # la fila antigua se migra, no se duplica


def test_concurrent_failures_are_all_counted(concurrent_db, clock):
    import threading

    from django.db import connection

    barrier = threading.Barrier(5)

    def run():
        try:
            barrier.wait()
            throttling.register_failure(EMAIL, IP)
        finally:
            connection.close()

    threads = [threading.Thread(target=run) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert AuthThrottle.objects.get().consecutive_failures == 5
    assert throttling.check(EMAIL) == 30
