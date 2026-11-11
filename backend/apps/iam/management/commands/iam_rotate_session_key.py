"""Retirada de una versión de la clave HMAC de sesión (T035; R2.6)."""

from django.core.management.base import BaseCommand, CommandError

from apps.core.keys import get_keyset
from apps.iam.models import UserSession


class Command(BaseCommand):
    help = "Borra las sesiones de una versión de SESSION_HMAC_KEYS ya retirada."

    def add_arguments(self, parser):
        parser.add_argument("--retire", required=True, help="Versión a retirar (p. ej. v1).")

    def handle(self, *args, **options):
        version = options["retire"]
        if version == get_keyset("SESSION_HMAC_KEYS").active_version:
            raise CommandError("No se puede retirar la versión activa de la clave de sesión.")
        deleted, _ = UserSession.objects.filter(key_version=version).delete()
        self.stdout.write(f"Sesiones retiradas de la versión {version}: {deleted}")
