"""Reloj inyectable (R16).

Todo el código de seguridad obtiene la hora con ``clock.now()``. Las pruebas parchean
``apps.core.clock.now`` para simular el paso del tiempo (caducidades, retrasos, TOTP) sin
dependencias adicionales.
"""

from datetime import datetime

from django.utils import timezone


def now() -> datetime:
    return timezone.now()


def default_now() -> datetime:
    """Para `default=` de los modelos: resuelve `now` en cada llamada, así que respeta el parche."""
    return now()
