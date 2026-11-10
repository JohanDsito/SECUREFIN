"""Procedimientos de consola del entorno controlado (T091, T092; FR-022, FR-023; contrato §7).

No tienen ninguna ruta HTTP: solo se invocan con `manage.py` dentro del contenedor `backend`.

- `bootstrap_first_admin`: crea el primer Administrador en `pending_activation`, sin contraseña
  (inutilizable) y con la activación encolada en el outbox. El enlace vale 24 h desde su entrega.
  Falla si ya existe cualquier Administrador, en cualquier estado.
  Limitación conocida (T140): si ese Administrador no activa su cuenta a tiempo, no hay todavía un
  procedimiento de consola para reenviarle la activación.
- `break_glass`: recuperación extraordinaria del último Administrador. Mismas garantías que el
  reinicio administrativo (FR-033, FR-035): invalida TOTP y códigos de recuperación, revoca todas las
  sesiones, no toca la contraseña ni concede sesión. Deja un `MfaResetCase` con
  `request_verification = console` como registro del procedimiento. Recupera el acceso relacionado
  con el MFA; la recuperación de contraseña queda pendiente de US7 (T141): hasta entonces no se
  encola ningún correo que el mailer no sepa entregar.

Ambas operaciones se serializan con bloqueos de PostgreSQL y escriben su evento en la misma
transacción (FR-044). Nunca devuelven ni imprimen tokens ni contraseñas.

`os_user` es la identidad efectiva del proceso: dentro del contenedor es el usuario `app` y no
identifica a la persona que ejecutó el comando en el host. La atribución humana depende del control
de acceso al host y a Docker y de sus registros del sistema.
"""

from __future__ import annotations

import getpass
import os

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.db import connection, transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.models import (
    MfaResetCase,
    MfaResetStatus,
    OutboxKind,
    RequestVerification,
    Role,
    Status,
    TOTPDevice,
    TOTPStatus,
    User,
)
from apps.iam.models.user import validate_no_control_chars
from apps.iam.services import outbox, session_admin
from apps.iam.services.mfa_reset import invalidate_mfa

# Clave arbitraria pero fija para pg_advisory_xact_lock: serializa dos bootstraps simultáneos.
_BOOTSTRAP_LOCK_KEY = 0x5EC0F1BA
MAX_REASON_LENGTH = 200


class ConsoleError(Exception):
    """Precondición incumplida; el comando sale con código distinto de 0."""


def os_user() -> str:
    """Usuario del sistema operativo que ejecuta el procedimiento (atribución, FR-041)."""
    try:
        return getpass.getuser()[:64]
    except (KeyError, OSError):  # contenedor sin entrada en /etc/passwd
        return (os.environ.get("USER") or f"uid:{os.getuid()}")[:64]


def _clean_identity(email: str, name: str) -> tuple[str, str]:
    email = User.objects.normalize_email(email)
    try:
        EmailValidator()(email)
    except ValidationError as exc:
        raise ConsoleError("El correo no es válido.") from exc
    name = (name or "").strip()
    if not name or len(name) > 100:
        raise ConsoleError("El nombre debe tener entre 1 y 100 caracteres.")
    try:
        validate_no_control_chars(name)
    except ValidationError as exc:
        raise ConsoleError("El nombre contiene caracteres no permitidos.") from exc
    return email, name


def clean_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ConsoleError("Indica el motivo con --reason.")
    if len(reason) > MAX_REASON_LENGTH:
        raise ConsoleError(f"El motivo no puede superar {MAX_REASON_LENGTH} caracteres.")
    try:
        validate_no_control_chars(reason)
    except ValidationError as exc:
        raise ConsoleError("El motivo contiene caracteres no permitidos.") from exc
    return reason


# --- T091 -------------------------------------------------------------------------------------------
def bootstrap_first_admin(email: str, name: str) -> User:
    email, name = _clean_identity(email, name)
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_BOOTSTRAP_LOCK_KEY])
        if User.objects.filter(role=Role.ADMIN).exists():
            raise ConsoleError("Ya existe un Administrador: el bootstrap solo se ejecuta una vez.")
        if User.objects.filter(email=email).exists():
            raise ConsoleError("Ya existe una cuenta con ese correo.")

        user = User(email=email, name=name, role=Role.ADMIN, status=Status.PENDING_ACTIVATION)
        user.set_unusable_password()
        user.save()
        outbox.enqueue(OutboxKind.ACCOUNT_ACTIVATION, user)
        record_event(
            "bootstrap_admin_executed",
            "success",
            target_type="user",
            target_id=user.id,
            metadata={"os_user": os_user()},
        )
    return user


# --- T092 -------------------------------------------------------------------------------------------
def break_glass_target(email: str) -> User:
    """Comprueba las precondiciones (sin efectos) y devuelve el Administrador afectado."""
    user = User.objects.filter(email=User.objects.normalize_email(email)).first()
    if user is None or user.role != Role.ADMIN:
        raise ConsoleError("El correo no corresponde a un Administrador.")
    if user.status != Status.ACTIVE:
        raise ConsoleError("La cuenta del Administrador no está activa.")
    others = (
        TOTPDevice.objects.filter(
            status=TOTPStatus.ACTIVE, user__role=Role.ADMIN, user__status=Status.ACTIVE
        )
        .exclude(user=user)
        .exists()
    )
    if others:
        raise ConsoleError(
            "Existe otro Administrador activo con MFA: usa el reinicio administrativo, no break-glass."
        )
    return user


def break_glass(email: str, reason: str) -> User:
    reason = clean_reason(reason)
    with transaction.atomic():
        # Bloquea los Administradores activos: nadie puede activar el MFA de otro mientras tanto.
        list(
            User.objects.select_for_update()
            .filter(role=Role.ADMIN, status=Status.ACTIVE)
            .order_by("id")
            .values_list("id", flat=True)
        )
        user = break_glass_target(email)  # se repite con los bloqueos tomados
        now = clock.now()

        # FR-033: invalida TOTP y códigos, revoca todas las sesiones. La contraseña no se toca.
        invalidate_mfa(user)
        session_admin.revoke_all(user, reason="break_glass")

        # Cierra cualquier caso abierto y deja constancia del procedimiento.
        MfaResetCase.objects.filter(
            target_user=user,
            status__in=[MfaResetStatus.REQUESTED, MfaResetStatus.PENDING_VERIFICATION],
        ).update(status=MfaResetStatus.CANCELLED, challenge_verifier=None, challenge_expires_at=None)
        MfaResetCase.objects.create(
            target_user=user,
            requested_by=user,
            request_verification=RequestVerification.CONSOLE,
            requested_at=now,
            status=MfaResetStatus.AUTHORIZED,
            authorized_at=now,
            verification_method="console:break_glass",
        )

        # No se encola `password_reset`: el mailer aún no tiene handler para ese tipo (llega con US7,
        # T113) y el mensaje acabaría en `failed`. Break-glass solo recupera el acceso del MFA; el
        # encolado se reincorpora en T141 cuando exista un handler funcional y probado.
        record_event(
            "break_glass_executed",
            "success",
            target_type="user",
            target_id=user.id,
            metadata={"os_user": os_user(), "reason": reason},
        )
    return user
