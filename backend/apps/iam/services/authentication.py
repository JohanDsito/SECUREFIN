"""Autenticación con contraseña y creación de la sesión (T054; FR-007 a FR-011, FR-025).

- Mismo fallo genérico para usuario inexistente, contraseña incorrecta o cuenta no activa (FR-009).
- Para un identificador inexistente se ejecuta un hash ficticio con los mismos parámetros, de modo
  que el tiempo de respuesta no revela si la cuenta existe (NFR-003).
- La sesión solo nace tras validar la contraseña (I1); su `created_at` es el origen del límite
  absoluto de 8 h y se hereda en las rotaciones (I3).
- Un rol con MFA obligatorio nunca recibe una sesión `full` sin MFA verificado (FR-025). En US1 se
  devuelve `mfa_enrollment_required` sin crear sesión; US3 añade la fase `pre_auth`.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

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


def start_full_session(request, user: User, source_ip: str | None) -> None:
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
        metadata={"auth_level": K.FULL},
    )


def password_login(request, email: str, password: str, source_ip: str | None) -> LoginResult:
    user = verify_password(email, password, source_ip)
    if user_mfa_enabled(user):
        return LoginResult(status="mfa_required", user=user)
    if mfa_required(user.role):
        return LoginResult(status="mfa_enrollment_required", user=user)
    start_full_session(request, user, source_ip)
    return LoginResult(status="authenticated", user=user)


def user_summary(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "mfa_enabled": user_mfa_enabled(user),
        "mfa_required": mfa_required(user.role),
    }
