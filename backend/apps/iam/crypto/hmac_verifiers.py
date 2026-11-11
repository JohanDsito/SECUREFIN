"""Verificadores HMAC-SHA-256 con una clave independiente por propósito (T029; R2, R7, R12; C1).

    session_verifier  -> SESSION_HMAC_KEYS   (dominio "securefin:session:")
    token_verifier    -> TOKEN_HMAC_KEYS     (dominio "<purpose>:")
    throttle_digest   -> THROTTLE_HMAC_KEYS  (dominio "throttle:acct:")

Ninguna función usa la clave de otra. Los verificadores de sesión llevan la versión de la clave
como prefijo (``v1$<hex64>``, máximo 72 caracteres) para poder rotar claves.
"""

from __future__ import annotations

import hashlib
import hmac

from apps.core.keys import get_keyset

SESSION_DOMAIN = "securefin:session:"
THROTTLE_DOMAIN = "throttle:acct:"


def _hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(expected: str, candidate: str) -> bool:
    """Comparación en tiempo constante."""
    return hmac.compare_digest(expected.encode("utf-8"), candidate.encode("utf-8"))


# --- Sesiones -----------------------------------------------------------------------------------
def session_verifier(session_key: str, version: str | None = None) -> str:
    keyset = get_keyset("SESSION_HMAC_KEYS")
    version = version or keyset.active_version
    return f"{version}${_hmac_hex(keyset.get(version), SESSION_DOMAIN + session_key)}"


def session_verifiers_accepted(session_key: str) -> list[str]:
    """Verificadores de la clave para cada versión aceptada (activa primero)."""
    keyset = get_keyset("SESSION_HMAC_KEYS")
    return [session_verifier(session_key, v) for v in keyset.accepted_versions]


def active_session_version() -> str:
    return get_keyset("SESSION_HMAC_KEYS").active_version


# --- Tokens de un solo uso ----------------------------------------------------------------------
def token_verifier(purpose: str, token: str, version: str | None = None) -> tuple[str, str]:
    """Devuelve ``(versión, hex64)`` del verificador del token para el propósito dado."""
    keyset = get_keyset("TOKEN_HMAC_KEYS")
    version = version or keyset.active_version
    return version, _hmac_hex(keyset.get(version), f"{purpose}:{token}")


def token_verifiers_accepted(purpose: str, token: str) -> list[tuple[str, str]]:
    keyset = get_keyset("TOKEN_HMAC_KEYS")
    return [token_verifier(purpose, token, v) for v in keyset.accepted_versions]


# --- Limitación por cuenta ----------------------------------------------------------------------
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def throttle_digest(email: str, version: str | None = None) -> tuple[str, str]:
    """Resumen seudonimizado del identificador: vale igual para cuentas inexistentes."""
    keyset = get_keyset("THROTTLE_HMAC_KEYS")
    version = version or keyset.active_version
    return version, _hmac_hex(keyset.get(version), THROTTLE_DOMAIN + normalize_email(email))


def throttle_digests_accepted(email: str) -> list[tuple[str, str]]:
    keyset = get_keyset("THROTTLE_HMAC_KEYS")
    return [throttle_digest(email, v) for v in keyset.accepted_versions]
