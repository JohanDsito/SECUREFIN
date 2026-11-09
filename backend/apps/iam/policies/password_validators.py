"""Política de contraseñas (T051; R4; FR-003, FR-004; NIST SP 800-63B).

15 a 128 caracteres, cualquier carácter imprimible (incluidos espacios y Unicode), sin reglas de
composición, con lista de bloqueo local (comunes, esperadas y comprometidas). Sin consultas externas.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path

from django.core.exceptions import ValidationError

MAX_PASSWORD_LENGTH = 128
SERVICE_TERMS = ("securefin", "secure fin", "gateway")
BLOCKLIST_PATH = Path(__file__).resolve().parent / "data" / "blocklist.txt"


def normalize_password(raw: str) -> str:
    """Normalización Unicode NFKC, idéntica en registro y en login (R4)."""
    return unicodedata.normalize("NFKC", raw or "")


class MaximumLengthValidator:
    def __init__(self, max_length: int = MAX_PASSWORD_LENGTH):
        self.max_length = max_length

    def validate(self, password, user=None):
        if len(password) > self.max_length:
            raise ValidationError(
                f"La contraseña no puede superar {self.max_length} caracteres.",
                code="password_too_long",
            )

    def get_help_text(self):
        return f"Como máximo {self.max_length} caracteres."


@lru_cache(maxsize=1)
def _blocklist() -> frozenset[str]:
    lines = BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))


class ServiceTermsBlocklistValidator:
    """Rechaza contraseñas con términos del servicio o presentes en la lista de bloqueo local."""

    def validate(self, password, user=None):
        lowered = normalize_password(password).lower()
        compact = "".join(ch for ch in lowered if ch.isalnum())
        if any(term.replace(" ", "") in compact for term in SERVICE_TERMS):
            raise ValidationError(
                "La contraseña no puede contener el nombre del servicio.", code="password_service_term"
            )
        if lowered in _blocklist():
            raise ValidationError(
                "La contraseña aparece en la lista de contraseñas comunes o comprometidas.",
                code="password_blocklisted",
            )

    def get_help_text(self):
        return "No puede contener el nombre del servicio ni ser una contraseña comprometida conocida."
