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


def fresh_totp(user) -> str:
    """Código TOTP actual de `user` tras liberar la antirrepetición (el login ya consumió el intervalo)."""
    from apps.iam.models import TOTPDevice

    TOTPDevice.objects.filter(user=user, status="active").update(last_used_timestep=None)
    return totp_code(user.totp_secret)


# --- Reinicio de MFA (US4) --------------------------------------------------------------------------
def requested_case(target):
    """Caso `requested` creado por el flujo real del servicio (el titular necesita MFA activo)."""
    from apps.iam.services import mfa_reset
    from apps.iam.services.mfa_state import user_mfa_enabled

    if not user_mfa_enabled(target):
        make_totp_device(target)
    return mfa_reset.request_reset(target)


def deliver_challenge_code(target) -> str:
    """Entrega el outbox y devuelve el código de 8 caracteres del último correo al titular."""
    import re

    from django.core import mail

    from apps.iam.services import outbox

    outbox.deliver_due()
    bodies = [m.body for m in mail.outbox if m.to == [target.email] and "verificación" in m.subject]
    match = re.search(r"^\s{4}([0-9A-Z]{8})$", bodies[-1], re.MULTILINE)
    assert match, "el correo del desafío no contiene el código"
    return match.group(1)


def opened_case(admin, target, channel: str = "in_person"):
    """Caso `pending_verification` abierto por `admin`; devuelve (caso, código del desafío)."""
    from apps.iam.services import mfa_reset

    case = requested_case(target)
    mfa_reset.open_case(admin, case.id, channel)
    return case, deliver_challenge_code(target)
