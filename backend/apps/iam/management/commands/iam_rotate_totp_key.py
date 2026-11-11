"""Rotación de la clave de cifrado de los secretos TOTP (T079; R8).

Recifra todos los TOTPDevice con `TOTP_ENCRYPTION_KEYS[vN]` en una única transacción: o se
recifran todos o ninguno. Cada recifrado usa un nonce nuevo. Solo informa del recuento; nunca
imprime secretos.

Procedimiento: añadir `totp_key_vN`, declarar `TOTP_KEY_VERSIONS=vN,vANTERIOR`, reiniciar,
ejecutar este comando y, después, retirar la versión anterior.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.core.keys import get_keyset
from apps.iam.crypto import aead
from apps.iam.models import TOTPDevice


class Command(BaseCommand):
    help = "Recifra todos los secretos TOTP con la versión de clave indicada."

    def add_arguments(self, parser):
        parser.add_argument("--to", required=True, dest="to", help="Versión destino (p. ej. v2).")

    def handle(self, *args, **options):
        target = options["to"]
        if target not in get_keyset(aead.KEYSET).accepted_versions:
            raise CommandError(f"La versión {target} no está configurada en TOTP_KEY_VERSIONS.")
        rotated = 0
        with transaction.atomic():
            for device in TOTPDevice.objects.select_for_update().exclude(key_version=target):
                try:
                    secret = aead.decrypt_totp_secret(
                        device.user_id, device.nonce, device.secret_ciphertext, device.key_version
                    )
                except aead.DecryptionError as exc:
                    raise CommandError(
                        f"No se pudo descifrar el dispositivo {device.id}; no se ha recifrado ninguno."
                    ) from exc
                encrypted = aead.encrypt_totp_secret(device.user_id, secret, version=target)
                device.secret_ciphertext = encrypted.ciphertext
                device.nonce = encrypted.nonce
                device.key_version = encrypted.key_version
                device.save(update_fields=["secret_ciphertext", "nonce", "key_version"])
                rotated += 1
        self.stdout.write(f"Dispositivos TOTP recifrados a {target}: {rotated}")
