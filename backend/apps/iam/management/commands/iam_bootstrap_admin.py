"""Creación del primer Administrador desde la consola del entorno controlado (T091; FR-022).

    docker compose -f infra/compose.yaml exec backend \
        python manage.py iam_bootstrap_admin --email admin@lab.securefin.local --name "Admin Lab"

- Solo funciona si no existe ningún Administrador (en cualquier estado); si no, sale con código ≠ 0.
- No acepta contraseñas: la cuenta queda en `pending_activation` y el enlace de activación (un solo
  uso, válido 24 h contadas desde la entrega del correo) llega al buzón de laboratorio por el outbox.
- Nunca imprime el enlace ni ningún secreto. Registra `bootstrap_admin_executed` con el usuario del
  sistema operativo (dentro del contenedor, `app`: no identifica a la persona del host).

Limitación conocida (T140): si este Administrador no activa la cuenta en 24 h o pierde el correo,
no existe aún un procedimiento de consola para reenviarle la activación (el bootstrap ya no se
ejecuta porque existe un Administrador y break-glass exige una cuenta activa). Debe resolverse antes
de producción; mientras tanto, activa la cuenta en cuanto llegue el correo.
"""

from django.core.management.base import BaseCommand, CommandError

from apps.iam.services import console


class Command(BaseCommand):
    help = "Crea el primer Administrador (pending_activation) y encola su correo de activación."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Correo del nuevo Administrador.")
        parser.add_argument("--name", required=True, help="Nombre visible del nuevo Administrador.")

    def handle(self, *args, **options):
        try:
            user = console.bootstrap_first_admin(options["email"], options["name"])
        except console.ConsoleError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS(
                f"Administrador {user.email} creado en pending_activation. El enlace de activación "
                "se enviará al buzón de laboratorio; configura el MFA en el primer acceso."
            )
        )
