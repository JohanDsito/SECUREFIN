"""TS-I14 / TS-I17 (T083): Pruebas de integración para administración y consola.

Comprueba:
- `iam_bootstrap_admin` falla si ya existe un Administrador y no imprime tokens ni secretos.
- `iam_break_glass` falla si existe otro Administrador activo con MFA y registra `break_glass_executed` con el usuario del SO.
- Con un fallo simulado de `record_event`, el cambio de rol y la desactivación se revierten (FR-044).
"""

from __future__ import annotations

import io
from unittest import mock
import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.audit.models import SecurityEvent
from apps.iam.models import Role, Status, User
from tests.helpers import make_totp_device

pytestmark = pytest.mark.integration


def test_bootstrap_admin_fails_if_admin_exists(make_user):
    """iam_bootstrap_admin se niega a crear un administrador si ya existe uno (código de salida != 0)."""
    # Ya existe un administrador en la BD
    make_user(role=Role.ADMIN, status=Status.ACTIVE)

    out = io.StringIO()
    err = io.StringIO()
    with pytest.raises(CommandError) as exc_info:
        call_command(
            "iam_bootstrap_admin",
            email="nuevo-admin@lab.securefin.local",
            name="Nuevo Admin",
            stdout=out,
            stderr=err,
        )

    # Debe fallar por lógica de negocio (ya existe administrador), no por comando desconocido
    assert "Unknown command" not in str(exc_info.value)
    combined = out.getvalue() + err.getvalue()
    assert "token" not in combined.lower()
    assert "password" not in combined.lower()


def test_bootstrap_admin_creates_pending_activation_when_no_admin_exists(db):
    """iam_bootstrap_admin crea el primer Administrador en pending_activation y registra evento."""
    User.objects.filter(role=Role.ADMIN).delete()

    out = io.StringIO()
    call_command(
        "iam_bootstrap_admin",
        email="primer-admin@lab.securefin.local",
        name="Primer Admin",
        stdout=out,
    )

    admin = User.objects.get(email="primer-admin@lab.securefin.local")
    assert admin.role == Role.ADMIN
    assert admin.status == Status.PENDING_ACTIVATION

    # Evento de auditoría bootstrap_admin_executed
    assert SecurityEvent.objects.filter(
        event_type="bootstrap_admin_executed",
        target_id=admin.id,
    ).exists()

    # Salida sin tokens
    assert "token" not in out.getvalue().lower()


def test_break_glass_fails_if_another_active_admin_with_mfa_exists(make_user):
    """iam_break_glass falla si existe otro Administrador activo con MFA."""
    admin1 = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    make_totp_device(admin1, status="active")

    admin2 = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    make_totp_device(admin2, status="active")

    out = io.StringIO()
    with pytest.raises(CommandError) as exc_info:
        call_command(
            "iam_break_glass",
            email=admin1.email,
            reason="Emergencia simulada",
            stdout=out,
        )
    # Debe fallar por la precondición de negocio, no por comando desconocido
    assert "Unknown command" not in str(exc_info.value)


def test_break_glass_succeeds_when_last_admin_lost_mfa(make_user):
    """iam_break_glass restablece el acceso del único Administrador e incluye usuario del SO."""
    # Solo existe admin1, o admin2 está desactivado / sin MFA
    admin = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    make_totp_device(admin, status="active")

    out = io.StringIO()
    with mock.patch("builtins.input", return_value="yes"):
        call_command(
            "iam_break_glass",
            email=admin.email,
            reason="Pérdida de dispositivo del único administrador",
            stdout=out,
        )

    # Evento registrado con metadata.os_user
    event = SecurityEvent.objects.filter(
        event_type="break_glass_executed",
        target_id=admin.id,
    ).first()
    assert event is not None
    assert "os_user" in event.metadata
    assert "reason" in event.metadata


def test_atomic_rollback_on_audit_failure_for_role_change(make_user):
    """Si record_event falla, el cambio de rol se revierte dentro de la transacción (FR-044)."""
    admin = make_user(role=Role.ADMIN)
    target = make_user(role=Role.CLIENT)

    from apps.iam.services import admin_users

    with mock.patch("apps.iam.services.admin_users.record_event", side_effect=RuntimeError("Fallo de auditoría")):
        with pytest.raises(RuntimeError):
            admin_users.change_role(admin, target, Role.AUDITOR)

    target.refresh_from_db()
    assert target.role == Role.CLIENT  # Revertido


def test_atomic_rollback_on_audit_failure_for_deactivation(make_user):
    """Si record_event falla, la desactivación se revierte dentro de la transacción (FR-044)."""
    admin = make_user(role=Role.ADMIN)
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)

    from apps.iam.services import admin_users

    with mock.patch("apps.iam.services.admin_users.record_event", side_effect=RuntimeError("Fallo de auditoría")):
        with pytest.raises(RuntimeError):
            admin_users.deactivate(admin, target)

    target.refresh_from_db()
    assert target.status == Status.ACTIVE  # Revertido
