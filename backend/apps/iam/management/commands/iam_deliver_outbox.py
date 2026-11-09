"""Proceso de entrega del outbox (servicio `mailer`; T044; R9). Solo imprime recuentos."""

import time

from django.core.management.base import BaseCommand

from apps.iam.services.outbox import deliver_due


class Command(BaseCommand):
    help = "Entrega los correos pendientes del outbox al buzón de laboratorio."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Procesa una sola vez y termina.")
        parser.add_argument("--interval", type=float, default=2.0)

    def handle(self, *args, **options):
        import apps.iam.services.handlers  # noqa: F401 - registra los handlers de cada historia

        while True:
            stats = deliver_due()
            if any(stats.values()):
                self.stdout.write(f"outbox sent={stats['sent']} retry={stats['retry']} failed={stats['failed']}")
            if options["once"]:
                return
            time.sleep(options["interval"])
