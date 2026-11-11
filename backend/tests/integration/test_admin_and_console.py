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


def test_bootstrap_admin_fails_even_if_existing_admin_is_pending(make_user):
    User.objects.filter(role=Role.ADMIN).delete()
    make_user(role=Role.ADMIN, status=Status.PENDING_ACTIVATION)
    with pytest.raises(CommandError):
        call_command("iam_bootstrap_admin", email="otro@lab.securefin.local", name="Otro", stdout=io.StringIO())
    assert User.objects.filter(role=Role.ADMIN).count() == 1


def test_bootstrap_admin_accepts_no_password_argument(db):
    with pytest.raises(CommandError):
        call_command(
            "iam_bootstrap_admin", "--email=a@lab.securefin.local", "--name=A", "--password=x", stdout=io.StringIO()
        )


def test_bootstrap_admin_rejects_invalid_email(db):
    User.objects.filter(role=Role.ADMIN).delete()
    with pytest.raises(CommandError):
        call_command("iam_bootstrap_admin", email="no-es-correo", name="A", stdout=io.StringIO())
    assert not User.objects.filter(role=Role.ADMIN).exists()


def test_bootstrap_admin_records_os_user_and_queues_activation(db):
    from apps.iam.models import OutboxMessage

    User.objects.filter(role=Role.ADMIN).delete()
    call_command("iam_bootstrap_admin", email="Primer@lab.securefin.local", name="Primer", stdout=io.StringIO())
    admin = User.objects.get(email="primer@lab.securefin.local")
    assert not admin.has_usable_password()
    assert OutboxMessage.objects.filter(user=admin, kind="account_activation").count() == 1
    event = SecurityEvent.objects.get(event_type="bootstrap_admin_executed", target_id=admin.id)
    assert event.metadata["os_user"]
    assert event.actor_id is None  # procedimiento de sistema, sin actor de la aplicación


def test_concurrent_bootstraps_create_a_single_admin(concurrent_db):
    import threading

    from django.db import connection

    User.objects.filter(role=Role.ADMIN).delete()
    barrier = threading.Barrier(2)
    errors = []

    def run(n):
        try:
            barrier.wait()
            call_command("iam_bootstrap_admin", email=f"boot{n}@lab.securefin.local", name=f"B{n}", stdout=io.StringIO())
        except CommandError as exc:
            errors.append(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=run, args=(n,)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 1
    assert User.objects.filter(role=Role.ADMIN).count() == 1


def test_break_glass_declined_changes_nothing(make_user):
    from apps.iam.models import OutboxMessage, TOTPDevice

    admin = make_user(role=Role.ADMIN, status=Status.ACTIVE)
    make_totp_device(admin)
    with mock.patch("builtins.input", return_value="no"), pytest.raises(CommandError):
        call_command("iam_break_glass", email=admin.email, reason="Prueba", stdout=io.StringIO())
    assert TOTPDevice.objects.filter(user=admin).exists()
    assert not OutboxMessage.objects.filter(user=admin).exists()
    assert not SecurityEvent.objects.filter(event_type="break_glass_executed").exists()


def test_break_glass_rejects_non_admin_and_does_not_prompt(make_user):
    client = make_user(role=Role.CLIENT)
    with mock.patch("builtins.input") as prompt, pytest.raises(CommandError):
        call_command("iam_break_glass", email=client.email, reason="Prueba", stdout=io.StringIO())
    prompt.assert_not_called()


def test_break_glass_allowed_when_other_admins_lack_mfa_or_are_deactivated(make_user):
    target = make_user(role=Role.ADMIN)
    make_totp_device(target)
    make_user(role=Role.ADMIN)  # activo sin MFA
    other = make_user(role=Role.ADMIN, status=Status.DEACTIVATED)
    make_totp_device(other)  # con MFA pero desactivado
    with mock.patch("builtins.input", return_value="yes"):
        call_command("iam_break_glass", email=target.email, reason="Prueba", stdout=io.StringIO())
    assert SecurityEvent.objects.filter(event_type="break_glass_executed", target_id=target.id).exists()


def test_break_glass_effects(make_user):
    from apps.iam.models import (
        MfaResetCase,
        OutboxMessage,
        RecoveryCode,
        RecoveryCodeStatus,
        TOTPDevice,
        UserSession,
    )
    from apps.iam.services import recovery_codes
    from tests.helpers import build_session

    admin = make_user(role=Role.ADMIN)
    make_totp_device(admin)
    recovery_codes.generate_batch(admin)
    build_session(admin)
    old_hash = admin.password
    out = io.StringIO()

    with mock.patch("builtins.input", return_value="yes"):
        call_command("iam_break_glass", email=admin.email, reason="Pérdida del móvil", stdout=out)

    admin.refresh_from_db()
    assert admin.password == old_hash and admin.status == Status.ACTIVE
    assert not TOTPDevice.objects.filter(user=admin).exists()
    assert not RecoveryCode.objects.filter(user=admin, status=RecoveryCodeStatus.AVAILABLE).exists()
    assert not UserSession.objects.filter(user=admin).exists()
    # H3: sin handler de password_reset (US7) no se encola nada que el mailer no pueda entregar
    assert not OutboxMessage.objects.filter(user=admin).exists()
    case = MfaResetCase.objects.get(target_user=admin)
    assert case.request_verification == "console" and case.status == "authorized"
    assert "token" not in out.getvalue().lower() and "#" not in out.getvalue()


# --- H1: vigencia real del enlace de activación del bootstrap ---------------------------------------
def test_bootstrap_activation_link_valid_24h_from_delivery(api, db, clock):
    """El token se emite al entregar el correo (no al ejecutar el comando) y vale exactamente 24 h."""
    import re

    from django.core import mail

    from tests.conftest import STRONG_PASSWORD

    User.objects.filter(role=Role.ADMIN).delete()
    call_command("iam_bootstrap_admin", email="boot@lab.securefin.local", name="Boot", stdout=io.StringIO())
    clock.advance(hours=5)  # el mailer entrega más tarde: la vigencia cuenta desde aquí
    call_command("iam_deliver_outbox", once=True, stdout=io.StringIO())
    body = next(m.body for m in mail.outbox if m.to == ["boot@lab.securefin.local"])
    assert "24 horas" in body
    token = re.search(r"/activate#token=([A-Za-z0-9_-]+)", body).group(1)

    clock.advance(hours=24, seconds=1)
    assert api.post("/auth/activate", {"token": token, "password": STRONG_PASSWORD}).status_code == 400
    assert User.objects.get(email="boot@lab.securefin.local").status == Status.PENDING_ACTIVATION


def test_bootstrap_activation_link_still_valid_just_before_24h(api, db, clock):
    import re

    from django.core import mail

    from tests.conftest import STRONG_PASSWORD

    User.objects.filter(role=Role.ADMIN).delete()
    call_command("iam_bootstrap_admin", email="boot@lab.securefin.local", name="Boot", stdout=io.StringIO())
    call_command("iam_deliver_outbox", once=True, stdout=io.StringIO())
    token = re.search(r"/activate#token=([A-Za-z0-9_-]+)", mail.outbox[-1].body).group(1)
    clock.advance(hours=23, minutes=59)
    assert api.post("/auth/activate", {"token": token, "password": STRONG_PASSWORD}).status_code == 204


# --- H3: nada que el mailer no pueda entregar ------------------------------------------------------
def test_console_procedures_only_enqueue_messages_the_mailer_can_deliver(make_user):
    """Bootstrap + break-glass y el mailer real (iam_deliver_outbox): todo se entrega, nada queda
    pendiente ni falla, y no existe ningún mensaje `password_reset` (sin handler hasta US7)."""
    from apps.iam.models import OutboxMessage, OutboxStatus

    User.objects.filter(role=Role.ADMIN).delete()
    call_command("iam_bootstrap_admin", email="boot@lab.securefin.local", name="Boot", stdout=io.StringIO())
    last_admin = make_user(role=Role.ADMIN)
    make_totp_device(last_admin)
    with mock.patch("builtins.input", return_value="yes"):
        call_command("iam_break_glass", email=last_admin.email, reason="Prueba", stdout=io.StringIO())

    out = io.StringIO()
    call_command("iam_deliver_outbox", once=True, stdout=out)
    assert OutboxMessage.objects.exists()
    assert set(OutboxMessage.objects.values_list("status", flat=True)) == {OutboxStatus.SENT}
    assert not OutboxMessage.objects.filter(kind="password_reset").exists()
    assert not SecurityEvent.objects.filter(event_type="email_delivery_failed").exists()


# --- H4: sin entrada interactiva -------------------------------------------------------------------
def _break_glass_state(admin):
    from apps.iam.models import MfaResetCase, OutboxMessage, TOTPDevice, UserSession

    return (
        TOTPDevice.objects.filter(user=admin).count(),
        UserSession.objects.filter(user=admin).count(),
        MfaResetCase.objects.filter(target_user=admin).count(),
        OutboxMessage.objects.filter(user=admin).count(),
        SecurityEvent.objects.filter(event_type="break_glass_executed").count(),
    )


def _closed_stdin():
    stream = io.StringIO()
    stream.close()
    return stream


@pytest.mark.parametrize(
    "stdin_factory",
    [lambda: io.StringIO(""), _closed_stdin, lambda: None],
    ids=["entrada-vacia-sin-tty", "entrada-cerrada", "sin-stdin"],
)
def test_break_glass_without_interactive_input_fails_cleanly(make_user, stdin_factory):
    from tests.helpers import build_session

    admin = make_user(role=Role.ADMIN)
    make_totp_device(admin)
    build_session(admin)
    before = _break_glass_state(admin)

    with mock.patch("sys.stdin", stdin_factory()), \
         mock.patch("apps.iam.services.console.break_glass") as effects, \
         pytest.raises(CommandError) as exc_info:
        call_command("iam_break_glass", email=admin.email, reason="Prueba", stdout=io.StringIO())

    assert "confirmación interactiva" in str(exc_info.value)
    effects.assert_not_called()  # nunca se llega a los efectos sin confirmación explícita
    assert _break_glass_state(admin) == before


def test_break_glass_ctrl_c_changes_nothing(make_user):
    admin = make_user(role=Role.ADMIN)
    make_totp_device(admin)
    before = _break_glass_state(admin)
    with mock.patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(CommandError):
        call_command("iam_break_glass", email=admin.email, reason="Prueba", stdout=io.StringIO())
    assert _break_glass_state(admin) == before


def test_break_glass_real_process_without_tty(concurrent_db, make_user):
    """Proceso real `manage.py iam_break_glass` con stdin cerrado (como `docker compose exec -T`
    sin entrada): código de salida 1, mensaje claro, sin traceback y sin cambios."""
    import os
    import subprocess
    import sys

    from django.conf import settings
    from django.db import connection

    admin = make_user(role=Role.ADMIN)
    make_totp_device(admin)
    before = _break_glass_state(admin)

    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "config.settings.test",
           "TEST_DB_NAME": connection.settings_dict["NAME"]}
    result = subprocess.run(  # noqa: S603 - argumentos fijos, sin shell
        [sys.executable, "manage.py", "iam_break_glass", "--email", admin.email, "--reason", "Prueba"],
        cwd=settings.BASE_DIR, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 1
    assert "confirmación interactiva" in result.stderr
    assert "Traceback" not in result.stderr
    assert _break_glass_state(admin) == before


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
