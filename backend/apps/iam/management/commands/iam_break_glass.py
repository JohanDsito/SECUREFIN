"""Recuperación extraordinaria del último Administrador (T092; FR-023; contrato §7).

    docker compose -f infra/compose.yaml exec backend \
        python manage.py iam_break_glass --email admin@lab.securefin.local --reason "Pérdida del móvil"

Precondición (contrato §7, sin endurecer): el correo es de un Administrador activo y no existe ningún
otro Administrador activo con MFA. Si lo hay, se usa el reinicio administrativo de la API. Se
permite aunque exista otro Administrador activo que aún no tenga MFA.

Exige confirmación interactiva: sin entrada interactiva (sin TTY, entrada cerrada o vacía) falla con
un error claro y sin modificar nada. Las precondiciones se comprueban antes de preguntar y se repiten
con los bloqueos tomados.

Efectos (FR-033, FR-035): invalida el TOTP y los códigos de recuperación y revoca todas las sesiones.
No cambia la contraseña ni concede sesión: el Administrador entra con su contraseña y configura de
nuevo el MFA. La recuperación de contraseña por correo queda pendiente de US7 (T141). Nunca imprime
tokens. Registra `break_glass_executed` con el usuario del sistema operativo y el motivo.

Limitaciones conocidas: dentro del contenedor `os_user` es `app` (la atribución humana depende de los
controles y registros del host); los intentos rechazados no generan eventos de auditoría de la
aplicación; no hay límite de frecuencia, porque ejecutar el comando ya exige privilegios sobre el
host y Docker y es una operación excepcional.
"""

from django.core.management.base import BaseCommand, CommandError

from apps.iam.services import console

CONFIRMATION = "yes"
NO_INPUT = (
    "Este procedimiento exige confirmación interactiva y no hay entrada disponible "
    "(ejecútalo con un terminal, p. ej. `docker compose exec` sin -T). No se ha modificado nada."
)


def _ask_confirmation(prompt: str) -> str:
    """Lee la confirmación. Sin terminal, con la entrada cerrada o interrumpida → CommandError."""
    try:
        return input(prompt)
    except EOFError as exc:  # entrada vacía o sin TTY
        raise CommandError(NO_INPUT) from exc
    except (ValueError, OSError, RuntimeError) as exc:  # sys.stdin cerrado o inexistente
        raise CommandError(NO_INPUT) from exc
    except KeyboardInterrupt as exc:
        raise CommandError("Procedimiento interrumpido: no se ha modificado nada.") from exc


class Command(BaseCommand):
    help = "Procedimiento extraordinario (break-glass) para recuperar el MFA del último Administrador."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Correo del Administrador afectado.")
        parser.add_argument("--reason", required=True, help="Motivo (queda en el registro de auditoría).")

    def handle(self, *args, **options):
        try:
            reason = console.clean_reason(options["reason"])
            user = console.break_glass_target(options["email"])  # precondiciones antes de preguntar
        except console.ConsoleError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            f"Vas a invalidar el MFA y revocar todas las sesiones de {user.email}. Su contraseña no "
            "cambia. La acción queda registrada en la auditoría."
        )
        answer = _ask_confirmation(f"Escribe '{CONFIRMATION}' para continuar: ")
        if answer.strip().lower() != CONFIRMATION:
            raise CommandError("Procedimiento cancelado: no se ha modificado nada.")

        try:
            console.break_glass(user.email, reason)
        except console.ConsoleError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS(
                "Procedimiento completado: MFA invalidado y sesiones revocadas. El Administrador "
                "iniciará sesión con su contraseña y configurará de nuevo el MFA."
            )
        )
