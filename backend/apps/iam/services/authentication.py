"""Autenticación con contraseña y creación de la sesión (T054; FR-007 a FR-011, FR-025).

- Mismo fallo genérico para usuario inexistente, contraseña incorrecta o cuenta no activa (FR-009).
- Para un identificador inexistente se ejecuta un hash ficticio con los mismos parámetros, de modo
  que el tiempo de respuesta no revela si la cuenta existe (NFR-003).
- La sesión solo nace tras validar la contraseña (I1); su `created_at` es el origen del límite
  absoluto de 8 h y se hereda en las rotaciones (I3).
- Un rol con MFA obligatorio nunca recibe una sesión `full` sin MFA verificado (FR-025).
- Fase `pre_auth` (T076; R13; U3): tras una contraseña válida, si hay MFA activo (5 min) o el rol lo
  exige sin tenerlo configurado (alta obligatoria, 10 min), se crea la primera fila de sesión con
  `_sf_pending_user_id` y **sin** `login()`: `request.user` sigue anónimo y ninguna ruta protegida
  responde. Al completar el MFA o el alta, `login()` rota la clave y la sesión pasa a `full`
  heredando el `created_at` inicial (I3).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.hashers import check_password, make_password

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.models import Status, User
from apps.iam.policies.matrix import mfa_required
from apps.iam.policies.password_validators import normalize_password
from apps.iam.services.mfa_state import user_mfa_enabled
from apps.iam.sessions import keys as K

BACKEND = "apps.iam.auth_backend.SessionUserBackend"


class AuthenticationFailedError(Exception):
    """Fallo genérico: nunca indica la causa al cliente."""


@dataclass
class LoginResult:
    status: str  # "authenticated" | "mfa_required" | "mfa_enrollment_required"
    user: User | None = None


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # Hash Argon2id con los mismos parámetros que las contraseñas reales.
    return make_password("securefin-dummy-password-for-timing-equalization")


def _fail(source_ip: str | None, user: User | None = None) -> None:
    record_event(
        "login_failed",
        "failure",
        actor_id=getattr(user, "id", None),
        actor_role=getattr(user, "role", None),
        source_ip=source_ip,
        metadata={"reason": "invalid_credentials", "stage": "password"},
    )
    raise AuthenticationFailedError


def verify_password(email: str, password: str, source_ip: str | None) -> User:
    """Valida identificador y contraseña. Lanza AuthenticationFailedError (genérico)."""
    email = (email or "").strip().lower()
    password = normalize_password(password)
    user = User.objects.filter(email=email).first()
    if user is None:
        check_password(password, _dummy_hash())
        _fail(source_ip)
    if not user.check_password(password):
        _fail(source_ip, user)
    if user.status != Status.ACTIVE:
        _fail(source_ip, user)
    return user


def start_pre_auth(request, user: User, ttl: int) -> None:
    """Crea la sesión `pre_auth`: correlaciona al usuario pendiente sin autenticarlo (U3, I1)."""
    session = request.session
    session.flush()  # identificador nuevo; no se mezcla con estado previo
    session[K.LEVEL] = K.PRE_AUTH
    session[K.PENDING_USER] = str(user.id)
    session[K.CREATED_AT] = clock.now().isoformat()
    session[K.PRE_AUTH_TTL] = ttl


def pending_user(request) -> User | None:
    """Usuario pendiente de la sesión `pre_auth` actual, solo si sigue activo."""
    session = request.session
    if session.get(K.LEVEL) != K.PRE_AUTH:
        return None
    user_id = session.get(K.PENDING_USER)
    if not user_id:
        return None
    return User.objects.filter(pk=user_id, status=Status.ACTIVE).first()


def start_full_session(request, user: User, source_ip: str | None, mfa_method: str | None = None) -> None:
    """Crea (o rota) la sesión `full` con origen de caducidad propio o heredado."""
    session = request.session
    now = clock.now()
    created_at = session.get(K.CREATED_AT)
    inherited = session.get(K.PENDING_USER) == str(user.id) and created_at
    if not inherited:
        # Sesión nueva: se descarta cualquier estado previo para no mezclar identidades.
        session.flush()
        created_at = now.isoformat()
    session[K.LEVEL] = K.FULL
    session[K.CREATED_AT] = created_at
    session[K.AUTHENTICATED_AT] = now.isoformat()
    login(request, user, backend=BACKEND)  # rota la clave (anti-fijación)
    session.pop(K.PENDING_USER, None)
    session.pop(K.PRE_AUTH_TTL, None)
    user.last_login_at = now
    user.save(update_fields=["last_login_at"])
    record_event(
        "login_succeeded",
        "success",
        actor=user,
        target_type="user",
        target_id=user.id,
        source_ip=source_ip,
        metadata={"auth_level": K.FULL, **({"mfa_method": mfa_method} if mfa_method else {})},
    )


def password_login(request, email: str, password: str, source_ip: str | None) -> LoginResult:
    user = verify_password(email, password, source_ip)
    cfg = settings.SECUREFIN_SESSION
    if user_mfa_enabled(user):
        start_pre_auth(request, user, cfg["PRE_AUTH_TTL"])
        return LoginResult(status="mfa_required", user=user)
    if mfa_required(user.role):
        start_pre_auth(request, user, cfg["PRE_AUTH_ENROLL_TTL"])
        return LoginResult(status="mfa_enrollment_required", user=user)
    start_full_session(request, user, source_ip)
    return LoginResult(status="authenticated", user=user)


def _mfa_failed(user: User, source_ip: str | None, reason: str) -> None:
    record_event(
        "login_failed",
        "failure",
        actor=user,
        source_ip=source_ip,
        metadata={"reason": reason, "stage": "mfa"},
    )
    raise AuthenticationFailedError


def complete_mfa(request, source_ip: str | None, totp_code: str | None = None,
                 recovery_code: str | None = None) -> tuple[User, int | None]:
    """Segundo paso del login: TOTP o código de recuperación (FR-008, FR-026, FR-029).

    Devuelve (usuario, códigos restantes si se usó uno de recuperación). Cualquier fallo es genérico.
    """
    from apps.iam.services import mfa, recovery_codes

    user = pending_user(request)
    if user is None or not user_mfa_enabled(user):
        raise AuthenticationFailedError
    remaining = None
    if totp_code is not None:
        if not mfa.verify_totp(user, totp_code):
            _mfa_failed(user, source_ip, "invalid_totp")
        method = "totp"
    else:
        remaining = recovery_codes.consume(user, recovery_code)
        if remaining is None:
            _mfa_failed(user, source_ip, "invalid_recovery_code")
        method = "recovery_code"
    start_full_session(request, user, source_ip, mfa_method=method)
    return user, remaining


def pending_enrollment_user(request) -> User | None:
    """Usuario en alta obligatoria: `pre_auth` y sin MFA activo (con MFA activo no se puede volver a
    dar de alta desde aquí; sería una forma de evitar el segundo factor)."""
    user = pending_user(request)
    if user is None or user_mfa_enabled(user) or not mfa_required(user.role):
        return None
    return user


def complete_enrollment(request, totp_code: str, source_ip: str | None) -> tuple[User, list[str]]:
    """Alta obligatoria durante el login: confirma el TOTP y pasa a `full` (FR-024, FR-025, FR-028)."""
    from apps.iam.services import mfa

    user = pending_enrollment_user(request)
    if user is None:
        raise AuthenticationFailedError
    try:
        codes = mfa.confirm_enrollment(user, totp_code, session=request.session, rotate=False)
    except mfa.MfaError as exc:
        raise AuthenticationFailedError from exc
    start_full_session(request, user, source_ip, mfa_method="enrollment")
    return user, codes


def user_summary(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "mfa_enabled": user_mfa_enabled(user),
        "mfa_required": mfa_required(user.role),
    }
