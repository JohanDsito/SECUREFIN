"""Generación de códigos legibles con CSPRNG en base32 de Crockford (T030; R6, R11).

El alfabeto excluye los caracteres ambiguos I, L, O y U (32 símbolos, 5 bits por carácter).

- Código de recuperación de MFA: 28 caracteres = 140 bits (>= 128), mostrado en 7 grupos de 4.
- Código de verificación del reinicio de MFA: 8 caracteres = 40 bits.
"""

from __future__ import annotations

import secrets

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BITS_PER_CHAR = 5
RECOVERY_CODE_LENGTH = 28
RECOVERY_CODE_GROUP = 4
VERIFICATION_CODE_LENGTH = 8

_EQUIVALENCES = str.maketrans({"I": "1", "L": "1", "O": "0"})


def _random_code(length: int) -> str:
    return "".join(secrets.choice(CROCKFORD_ALPHABET) for _ in range(length))


def generate_recovery_code() -> str:
    """Código de recuperación normalizado (sin guiones)."""
    return _random_code(RECOVERY_CODE_LENGTH)


def generate_verification_code() -> str:
    return _random_code(VERIFICATION_CODE_LENGTH)


def format_code(code: str, group: int = RECOVERY_CODE_GROUP) -> str:
    return "-".join(code[i : i + group] for i in range(0, len(code), group))


def normalize_code(raw: str) -> str | None:
    """Normaliza la entrada del usuario; devuelve None si contiene símbolos fuera del alfabeto."""
    if raw is None:
        return None
    cleaned = raw.upper().replace("-", "").replace(" ", "").translate(_EQUIVALENCES)
    if not cleaned or any(ch not in CROCKFORD_ALPHABET for ch in cleaned):
        return None
    return cleaned


def entropy_bits(length: int) -> int:
    return length * BITS_PER_CHAR
