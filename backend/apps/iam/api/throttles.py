"""Limitación por IP de las rutas de autenticación (T101; R12; FR-037, FR-039).

Throttles de DRF por ámbito sobre `DatabaseCache` (sin Redis). La IP es la que fija Nginx en
`X-Forwarded-For` (`NUM_PROXIES = 1`), la misma que usan los eventos (`client_ip`). Al superar el
límite: `429` con `Retry-After` y evento `throttle_ip_limited` (sin la IP en los metadatos; la IP va
en `source_ip`, como en el resto de eventos de autenticación).

Umbrales (research R12): login 20/min, mfa 10/min, register 5/h, activation 10/h,
mfa_reset_request 3/día. `recovery` (5/h) se define aquí y lo asigna US7 (T114).

Complementa, no sustituye, a la limitación por cuenta con retrasos progresivos (T098–T100), que
sigue pendiente.
"""

from __future__ import annotations

from rest_framework.throttling import ScopedRateThrottle

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.sessions.middleware import client_ip


class IpScopedRateThrottle(ScopedRateThrottle):
    """`ScopedRateThrottle` por IP de cliente; solo actúa en vistas con `throttle_scope`."""

    def timer(self):  # reloj inyectable del proyecto (permite probar la ventana con reloj simulado)
        return clock.now().timestamp()

    def get_cache_key(self, request, view):
        ip = client_ip(request) or self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ip}

    def throttle_failure(self):
        record_event(
            "throttle_ip_limited",
            "denied",
            source_ip=self._source_ip,
            metadata={"scope": self.scope},
        )
        return False

    def allow_request(self, request, view):
        self._source_ip = client_ip(request)
        return super().allow_request(request, view)
