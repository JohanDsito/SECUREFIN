"""Administración de usuarios y roles por Administradores (T086; FR-012, FR-019, FR-020, FR-044).

- Listado con filtros y paginación.
- Alta de cuentas privilegiadas (Admin/Auditor) en pending_activation con enlace por outbox.
- Cambio de rol, desactivación y reactivación.
- Prohibición estricta de autooperaciones (403).
- Protección transaccional del último Administrador activo (409) con select_for_update.
- Revocación inmediata de sesiones y registro de eventos en la misma transacción atómica (FR-044).
"""

from __future__ import annotations

from django.core.paginator import Paginator
from django.db import IntegrityError, transaction

from apps.audit.services import record_event
from apps.iam.models import Role, Status, User
from apps.iam.services import outbox, session_admin


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


def list_users(
    role: str | None = None,
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
):
    """Lista usuarios con filtros opcionales de rol y estado, paginados."""
    qs = User.objects.all().order_by("-created_at")
    if role and role in Role.values:
        qs = qs.filter(role=role)
    if status and status in Status.values:
        qs = qs.filter(status=status)

    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)
    return page_obj


def create_privileged_user(
    admin_user: User,
    email: str,
    name: str,
    role: str,
    source_ip: str | None = None,
) -> User:
    """Crea una cuenta privilegiada (admin o auditor) en pending_activation y encola activación."""
    if role not in (Role.ADMIN, Role.AUDITOR):
        raise InvalidRoleError("Solo se pueden crear usuarios con rol admin o auditor.")

    email_clean = (email or "").strip().lower()
    name_clean = (name or "").strip()

    if User.objects.filter(email=email_clean).exists():
        raise UserAlreadyExistsError("El usuario ya se encuentra registrado.")

    user = User(
        email=email_clean,
        name=name_clean,
        role=role,
        status=Status.PENDING_ACTIVATION,
    )
    user.set_unusable_password()

    try:
        with transaction.atomic():
            user.save()
            outbox.enqueue("account_activation", user)
            record_event(
                "account_created_by_admin",
                "success",
                actor=admin_user,
                target_type="user",
                target_id=user.id,
                source_ip=source_ip,
                metadata={"role": role},
            )
    except IntegrityError as exc:
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
        raise InvalidRoleError(f"Rol desconocido: {new_role}")

    with transaction.atomic():
        # Bloquear fila del usuario destino
        target = User.objects.select_for_update().get(id=target_user.id)

        # Si se degrada a un Administrador activo, verificar que no sea el último
        if target.role == Role.ADMIN and new_role != Role.ADMIN and target.status == Status.ACTIVE:
            active_admin_count = (
                User.objects.select_for_update()
                .filter(role=Role.ADMIN, status=Status.ACTIVE)
                .count()
            )
            if active_admin_count <= 1:
                raise LastAdminError("No se puede degradar al último administrador activo.")

        old_role = target.role
        target.role = new_role
        target_user.role = new_role
        target.save(update_fields=["role"])

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
    """Desactiva una cuenta. Revoca sesiones y audita en la misma transacción."""
    if admin_user.id == target_user.id:
        raise SelfOperationError("Un administrador no puede desactivar su propia cuenta.")

    with transaction.atomic():
        target = User.objects.select_for_update().get(id=target_user.id)

        # Si se desactiva a un Administrador activo, verificar que no sea el último
        if target.role == Role.ADMIN and target.status == Status.ACTIVE:
            active_admin_count = (
                User.objects.select_for_update()
                .filter(role=Role.ADMIN, status=Status.ACTIVE)
                .count()
            )
            if active_admin_count <= 1:
                raise LastAdminError("No se puede desactivar al último administrador activo.")

        target.status = Status.DEACTIVATED
        target_user.status = Status.DEACTIVATED
        target.save(update_fields=["status"])

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
    """Reactiva una cuenta desactivada y audita el cambio."""
    with transaction.atomic():
        target = User.objects.select_for_update().get(id=target_user.id)
        target.status = Status.ACTIVE
        target.save(update_fields=["status"])

        record_event(
            "account_reactivated",
            "success",
            actor=admin_user,
            target_type="user",
            target_id=target.id,
            source_ip=source_ip,
        )

    return target


def resend_activation(
    admin_user: User,
    target_user: User,
) -> None:
    """Reenvía la activación encolando un nuevo mensaje en el outbox si sigue pendiente."""
    if target_user.status != Status.PENDING_ACTIVATION:
        raise InvalidStatusError("Solo se puede reenviar activación a cuentas pendientes.")

    outbox.enqueue("account_activation", target_user)
