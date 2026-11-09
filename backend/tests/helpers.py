"""Utilidades de prueba compartidas."""

from __future__ import annotations

from apps.core import clock
from apps.iam.sessions import keys as K
from apps.iam.sessions.store import SessionStore

BACKEND = "apps.iam.auth_backend.SessionUserBackend"
COOKIE = "__Host-sf_session"


def build_session(user, level: str = K.FULL, created_at=None, ttl: int | None = None) -> str:
    """Crea una sesión persistida directamente en el motor y devuelve su clave en claro."""
    store = SessionStore()
    store[K.LEVEL] = level
    store[K.CREATED_AT] = (created_at or clock.now()).isoformat()
    if level == K.FULL:
        store[K.DJANGO_USER] = str(user.id)
        store["_auth_user_backend"] = BACKEND
        store["_auth_user_hash"] = user.get_session_auth_hash()
        store[K.AUTHENTICATED_AT] = clock.now().isoformat()
    else:
        store[K.PENDING_USER] = str(user.id)
        if ttl:
            store[K.PRE_AUTH_TTL] = ttl
    store.create()
    return store.session_key


def use_session(api, key: str) -> None:
    api.client.cookies[COOKIE] = key


def session_cookie_set(response) -> bool:
    """True si la respuesta emite Set-Cookie para la cookie de sesión (con valor no vacío)."""
    morsel = response.cookies.get(COOKIE)
    return morsel is not None and morsel.value != ""


def session_cookie_deleted(response) -> bool:
    morsel = response.cookies.get(COOKIE)
    return morsel is not None and morsel.value == ""


# --- MFA (US3) --------------------------------------------------------------------------------------
TOTP_PERIOD = 30


def make_totp_device(user, status: str = "active", secret: str | None = None) -> str:
    """Crea un TOTPDevice cifrado igual que el servicio y devuelve el secreto base32 (solo pruebas)."""
    import pyotp

    from apps.iam.crypto import aead
    from apps.iam.models import TOTPDevice

    secret = secret or pyotp.random_base32(32)
    encrypted = aead.encrypt_totp_secret(user.id, secret)
    TOTPDevice.objects.create(
        user=user,
        status=status,
        secret_ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        key_version=encrypted.key_version,
        confirmed_at=clock.now() if status == "active" else None,
    )
    return secret


def totp_code(secret: str, at=None, steps: int = 0) -> str:
    """Código TOTP para el instante `at` (por defecto, clock.now()) desplazado `steps` intervalos."""
    import pyotp
    from datetime import timedelta

    moment = (at or clock.now()) + timedelta(seconds=steps * TOTP_PERIOD)
    return pyotp.TOTP(secret).at(moment)
