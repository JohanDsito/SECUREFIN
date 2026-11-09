"""Registro central de los handlers del outbox.

Cada historia añade aquí la importación de su módulo de handlers (activación en US4, recuperación
en US7, reinicio de MFA en US4). Importar este módulo registra todos los disponibles.
"""

from apps.iam.services import activation, mfa_reset  # noqa: F401
