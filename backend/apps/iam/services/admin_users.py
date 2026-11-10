"""Administración de usuarios y roles por Administradores (T086; FR-012, FR-019, FR-020, FR-044).

- Listado con filtros y paginación (sin N+1: `mfa_enabled` se anota con EXISTS).
- Alta de cuentas privilegiadas (Admin/Auditor) en pending_activation con enlace por outbox.
- Cambio de rol, desactivación y reactivación según el diagrama de estados de data-model:
  active → deactivated → active; cualquier otra transición → InvalidStatusError (409).
- Prohibición estricta de autooperaciones (403).
- Invariante "al menos un Administrador activo" (409): se bloquean con SELECT … FOR UPDATE, en orden
  de id, todas las filas de Administradores activos y después la del objetivo. Así dos
  Administradores que se degradan mutuamente se serializan en lugar de interbloquearse.
- Revocación de sesiones y evento de auditoría en la misma transacción atómica (FR-012, FR-044).
"""

from __future__ import annotations

import uuid

from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Exists, OuterRef

from apps.audit.services import record_event
from apps.iam.models import OutboxKind, Role, Status, TOTPDevice, TOTPStatus, User
from apps.iam.services import outbox, session_admin

PAGE_SIZE = 20
PRIVILEGED_ROLES = (Role.ADMIN, Role.AUDITOR)


class AdminOperationError(Exception):
    """Error base en operaciones administrativas."""


class SelfOperationError(AdminOperationError):
    """Intento de operar sobre sí mismo (cambiar propio rol, desactivarse o reiniciar propio MFA)."""


class LastAdminError(AdminOperationError):
    """Intento de degradar o desactivar al último administrador activo."""


class InvalidRoleError(AdminOperationError):
    """Rol inválido o no permitido."""


class InvalidStatusError(AdminOperationError):
    """Estado inválido para la operación."""


class UserAlreadyExistsError(AdminOperationError):
    """El correo ya está registrado en el sistema."""


class UserNotFoundError(AdminOperationError):
    """No existe ningún usuario con ese identificador (o el identificador está mal formado)."""


class ActorNotAdminError(AdminOperationError):
    """El actor dejó de ser Administrador activo mientras esperaba el bloqueo (carrera)."""


# --- Consultas --------------------------------------------------------------------------------------
def list_users(role: str | None = None, status: str | None = None, page: int = 1, page_size: int = PAGE_SIZE):
    """Página de usuarios con filtros opcionales; cada fila lleva `mfa_enabled` anotado."""
    qs = User.objects.annotate(
        mfa_enabled=Exists(TOTPDevice.objects.filter(user=OuterRef("pk"), status=TOTPStatus.ACTIVE))
    ).order_by("-created_at", "id")
    if role:
        qs = qs.filter(role=role)
    if status:
        qs = qs.filter(status=status)
    return Paginator(qs, page_size).get_page(page)


def get_user(user_id) -> User:
    """Usuario por id; inexistente o mal formado → UserNotFoundError (la vista responde 404)."""
    try:
        pk = uuid.UUID(str(user_id))
    except ValueError as exc:
        raise UserNotFoundError from exc
    user = User.objects.filter(pk=pk).first()
    if user is None:
        raise UserNotFoundError
    return user


# --- Bloqueos ---------------------------------------------------------------------------------------
def _lock_admins_and_target(target_id) -> tuple[User, list]:
    """Bloquea (en orden de id) los Administradores activos y después el objetivo."""
    admin_ids = list(
        User.objects.select_for_update()
        .filter(role=Role.ADMIN, status=Status.ACTIVE)
        .order_by("id")
        .values_list("id", flat=True)
    )
    return User.objects.select_for_update().get(pk=target_id), admin_ids


def _check_invariants(actor: User, target: User, admin_ids: list, removes_admin: bool) -> None:
    """Con los bloqueos tomados: primero el invariante del último Administrador (409) y después que
    el actor siga siendo Administrador activo (otra transacción pudo degradarlo mientras esperaba)."""
    if removes_admin and target.role == Role.ADMIN and target.status == Status.ACTIVE and len(admin_ids) <= 1:
        raise LastAdminError("No se puede degradar ni desactivar al último administrador activo.")
    if actor.id not in admin_ids:
        raise ActorNotAdminError("El actor ya no es un Administrador activo.")


def _sync(instance: User, fresh: User, *fields: str) -> None:
    """Refleja en el objeto del llamador los campos cambiados en la fila bloqueada."""
    for field in fields:
        setattr(instance, field, getattr(fresh, field))


# --- Operaciones ------------------------------------------------------------------------------------
def create_privileged_user(
    admin_user: User,
    email: str,
    name: str,
    role: str,
    source_ip: str | None = None,
) -> User:
    """Crea una cuenta privilegiada (admin o auditor) en pending_activation y encola activación."""
    if role not in PRIVILEGED_ROLES:
        raise InvalidRoleError("Solo se pueden crear usuarios con rol admin o auditor.")

    email_clean = User.objects.normalize_email(email)
    name_clean = (name or "").strip()

    if User.objects.filter(email=email_clean).exists():
        raise UserAlreadyExistsError("El usuario ya se encuentra registrado.")

    user = User(email=email_clean, name=name_clean, role=role, status=Status.PENDING_ACTIVATION)
    user.set_unusable_password()

    try:
        with transaction.atomic():
            user.save()
            outbox.enqueue(OutboxKind.ACCOUNT_ACTIVATION, user)
            record_event(
                "account_created_by_admin",
                "success",
                actor=admin_user,
                target_type="user",
                target_id=user.id,
                source_ip=source_ip,
                metadata={"role": role},
            )
    except IntegrityError as exc:  # carrera con otra alta del mismo correo (índice único)
        raise UserAlreadyExistsError("El usuario ya existe.") from exc

    return user


def change_role(
    admin_user: User,
    target_user: User,
    new_role: str,
    source_ip: str | None = None,
) -> User:
    """Modifica el rol de un usuario. Revoca sesiones y audita en la misma transacción."""
    if admin_user.id == target_user.id:
        raise SelfOperationError("Un administrador no puede modificar su propio rol.")
    if new_role not in Role.values:
        raise InvalidRoleError("Rol desconocido.")

    with transaction.atomic():
        target, admin_ids = _lock_admins_and_target(target_user.id)
        _check_invariants(admin_user, target, admin_ids, removes_admin=new_role != Role.ADMIN)
        if target.role == new_role:
            return target  # sin cambios: ni revocación ni evento

        old_role = target.role
        target.role = new_role
        target.save(update_fields=["role"])
        _sync(target_user, target, "role")

        session_admin.revoke_all(target, actor=admin_user, reason="role_changed")
        record_event(
            "role_changed",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=target.id,
            source_ip=source_ip,
            metadata={"from_role": old_role, "to_role": new_role},
        )
    return target


def deactivate(
    admin_user: User,
    target_user: User,
    source_ip: str | None = None,
) -> User:
    """Desactiva una cuenta activa. Revoca sesiones y audita en la misma transacción."""
    if admin_user.id == target_user.id:
        raise SelfOperationError("Un administrador no puede desactivar su propia cuenta.")

    with transaction.atomic():
        target, admin_ids = _lock_admins_and_target(target_user.id)
        _check_invariants(admin_user, target, admin_ids, removes_admin=True)
        if target.status != Status.ACTIVE:
            raise InvalidStatusError("Solo se pueden desactivar cuentas activas.")

        target.status = Status.DEACTIVATED
        target.save(update_fields=["status"])
        _sync(target_user, target, "status")

        session_admin.revoke_all(target, actor=admin_user, reason="account_deactivated")
        record_event(
            "account_deactivated",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=target.id,
            source_ip=source_ip,
        )
    return target


def reactivate(
    admin_user: User,
    target_user: User,
    source_ip: str | None = None,
) -> User:
    """Reactiva una cuenta desactivada; revoca sus sesiones (FR-012 e) y audita."""
    if admin_user.id == target_user.id:
        raise SelfOperationError("Un administrador no puede reactivar su propia cuenta.")

    with transaction.atomic():
        target = User.objects.select_for_update().get(pk=target_user.id)
        if target.status != Status.DEACTIVATED:
            raise InvalidStatusError("Solo se pueden reactivar cuentas desactivadas.")

        target.status = Status.ACTIVE
        target.save(update_fields=["status"])
        _sync(target_user, target, "status")

        session_admin.revoke_all(target, actor=admin_user, reason="account_reactivated")
        record_event(
            "account_reactivated",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=target.id,
            source_ip=source_ip,
        )
    return target


def resend_activation(admin_user: User, target_user: User) -> None:
    """Encola un nuevo correo de activación para una cuenta pendiente.

    El token se genera al entregar e invalida el anterior (tokens.issue). El catálogo cerrado de
    eventos no tiene un tipo propio para el reenvío: la entrega queda registrada con
    `activation_sent` (o `email_delivery_failed`).
    """
    with transaction.atomic():
        target = User.objects.select_for_update().get(pk=target_user.id)
        if target.status != Status.PENDING_ACTIVATION:
            raise InvalidStatusError("Solo se puede reenviar la activación a cuentas pendientes.")
        outbox.enqueue(OutboxKind.ACCOUNT_ACTIVATION, target)
