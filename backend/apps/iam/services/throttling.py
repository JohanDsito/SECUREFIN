"""Limitación progresiva por cuenta y detección de relleno de credenciales (T099; R12; FR-036–FR-039).

Por cuenta (`AuthThrottle`):
- Desde el 5.º fallo consecutivo: retraso de 30 s · 2^(n−5), con tope de 900 s (15 min). Nunca hay
  bloqueo permanente (FR-038): al terminar el retraso se vuelve a evaluar.
- Durante el retraso, `check()` > 0 y el llamador rechaza SIN evaluar credenciales (ni el hasher).
- El contador se reinicia tras una autenticación COMPLETA (`register_success`) o tras 30 min sin fallos.
- El identificador se guarda solo como HMAC (THROTTLE_HMAC_KEYS): funciona igual para correos
  inexistentes y no revela cuáles existen.
- Rotación de clave: `check()` consulta todas las versiones aceptadas y aplica el retraso más
  restrictivo; `register_failure()` escribe en la versión activa, heredando el contador de la fila de
  la versión anterior, que se elimina.

Por origen: `register_failure()` anota el resumen del identificador por IP (caché en base de datos,
sin Redis); con 10 o más identificadores distintos en 15 min se registra `credential_stuffing_suspected`
una vez por ventana. La limitación por IP propiamente dicha está en `apps.iam.api.throttles` (T101).
"""

from __future__ import annotations

import math
from datetime import timedelta

from django.core.cache import cache
from django.db import IntegrityError, transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.crypto import hmac_verifiers
from apps.iam.models import AuthThrottle, ThrottleScope

FAILURE_THRESHOLD = 5
BASE_DELAY_SECONDS = 30
MAX_DELAY_SECONDS = 900
RESET_AFTER = timedelta(minutes=30)
STUFFING_DISTINCT_IDENTIFIERS = 10
STUFFING_WINDOW = timedelta(minutes=15)
_STUFFING_CACHE_PREFIX = "securefin:stuffing:"


def delay_for(failures: int) -> int:
    """Retraso en segundos tras `failures` fallos consecutivos."""
    if failures < FAILURE_THRESHOLD:
        return 0
    return min(BASE_DELAY_SECONDS * 2 ** (failures - FAILURE_THRESHOLD), MAX_DELAY_SECONDS)


def _accepted(email: str) -> list[tuple[str, str]]:
    """[(versión, resumen)] para cada versión aceptada de la clave; la activa primero."""
    return hmac_verifiers.throttle_digests_accepted(email)


# --- Consulta ---------------------------------------------------------------------------------------
def check(email: str) -> int:
    """Segundos que faltan para poder intentarlo (0 = permitido). No modifica nada."""
    now = clock.now()
    digests = [digest for _version, digest in _accepted(email)]
    until = (
        AuthThrottle.objects.filter(scope=ThrottleScope.ACCOUNT, key_digest__in=digests, blocked_until__gt=now)
        .order_by("-blocked_until")
        .values_list("blocked_until", flat=True)
        .first()
    )
    if until is None:
        return 0
    return max(1, math.ceil((until - now).total_seconds()))


# --- Registro ---------------------------------------------------------------------------------------
def _locked_active_row(accepted: list[tuple[str, str]], now) -> AuthThrottle:
    """Fila de la versión activa, bloqueada, con el estado de versiones anteriores ya fusionado."""
    active_version, active_digest = accepted[0]
    rows = list(
        AuthThrottle.objects.select_for_update()
        .filter(scope=ThrottleScope.ACCOUNT, key_digest__in=[d for _v, d in accepted])
        .order_by("key_digest")
    )
    active = next((r for r in rows if r.key_digest == active_digest), None)
    if active is None:
        try:
            with transaction.atomic():
                active = AuthThrottle.objects.create(
                    scope=ThrottleScope.ACCOUNT,
                    key_digest=active_digest,
                    key_version=active_version,
                    consecutive_failures=0,
                    last_failure_at=now,
                )
        except IntegrityError:  # otra transacción la creó a la vez: se espera su bloqueo
            active = AuthThrottle.objects.select_for_update().get(
                scope=ThrottleScope.ACCOUNT, key_digest=active_digest
            )
    for old in (r for r in rows if r.pk != active.pk):  # rotación: hereda y elimina la fila antigua
        active.consecutive_failures = max(active.consecutive_failures, old.consecutive_failures)
        active.last_failure_at = max(active.last_failure_at, old.last_failure_at)
        if old.blocked_until and (active.blocked_until is None or old.blocked_until > active.blocked_until):
            active.blocked_until = old.blocked_until
        old.delete()
    return active


def register_failure(email: str, source_ip: str | None = None) -> int:
    """Anota un fallo de autenticación para el identificador. Devuelve el retraso aplicado (s)."""
    now = clock.now()
    accepted = _accepted(email)
    with transaction.atomic():
        row = _locked_active_row(accepted, now)
        if row.consecutive_failures and row.last_failure_at <= now - RESET_AFTER:
            row.consecutive_failures = 0  # 30 min sin fallos: se empieza de cero
            row.blocked_until = None
        row.consecutive_failures += 1
        row.last_failure_at = now
        delay = delay_for(row.consecutive_failures)
        row.blocked_until = now + timedelta(seconds=delay) if delay else None
        row.save(update_fields=["consecutive_failures", "last_failure_at", "blocked_until", "key_version"])
        if delay:
            record_event(
                "throttle_account_delay",
                "denied",
                source_ip=source_ip,
                metadata={"delay_seconds": delay, "failures": row.consecutive_failures},
            )
        if source_ip:
            _note_identifier_for_ip(source_ip, accepted[0][1], now)
    return delay


def register_success(email: str) -> None:
    """Autenticación completa: el contador del identificador se borra (todas las versiones)."""
    AuthThrottle.objects.filter(
        scope=ThrottleScope.ACCOUNT, key_digest__in=[d for _v, d in _accepted(email)]
    ).delete()


# --- Relleno de credenciales (FR-039) ---------------------------------------------------------------
def _note_identifier_for_ip(source_ip: str, digest: str, now) -> None:
    """Identificadores distintos con fallos desde una IP en la ventana; alerta una vez por ventana.

    Solo se guarda un prefijo del resumen HMAC (nunca el correo) y caduca con la ventana. La lectura y
    escritura no son atómicas: es una detección aproximada, suficiente para generar la alerta.
    """
    key = f"{_STUFFING_CACHE_PREFIX}{source_ip}"
    window = STUFFING_WINDOW.total_seconds()
    ts = now.timestamp()
    state = cache.get(key) or {"ids": {}, "flagged_at": None}
    ids = {d: t for d, t in state["ids"].items() if t > ts - window}
    ids[digest[:16]] = ts
    flagged_at = state.get("flagged_at")
    if flagged_at is not None and flagged_at <= ts - window:
        flagged_at = None
    if len(ids) >= STUFFING_DISTINCT_IDENTIFIERS and flagged_at is None:
        record_event(
            "credential_stuffing_suspected",
            "denied",
            source_ip=source_ip,
            metadata={
                "distinct_identifiers": len(ids),
                "window_minutes": int(STUFFING_WINDOW.total_seconds() // 60),
            },
        )
        flagged_at = ts
    cache.set(key, {"ids": ids, "flagged_at": flagged_at}, timeout=int(window) + 60)
