"""Cifrado autenticado de los secretos TOTP (T072; R5, R8).

- AES-256-GCM (`cryptography`) con la clave `TOTP_ENCRYPTION_KEYS[versión]`.
- Nonce aleatorio de 96 bits por operación (nunca se reutiliza con la misma clave).
- AAD = "securefin:totp:v1:" + user_id: un texto cifrado copiado a la fila de otro usuario no se
  descifra (falla la autenticación GCM).

Un secreto TOTP debe poder recuperarse para calcular códigos, así que se cifra en lugar de
guardarse como hash. Los errores nunca incluyen el secreto ni la clave.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apps.core.keys import get_keyset

KEYSET = "TOTP_ENCRYPTION_KEYS"
AAD_PREFIX = "securefin:totp:v1:"
NONCE_BYTES = 12


class DecryptionError(Exception):
    """El texto cifrado no se pudo autenticar (alterado, de otro usuario o versión desconocida)."""


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: bytes
    nonce: bytes
    key_version: str


def aad_for(user_id) -> bytes:
    return f"{AAD_PREFIX}{user_id}".encode()


def active_version() -> str:
    return get_keyset(KEYSET).active_version


def encrypt_totp_secret(user_id, secret: str, version: str | None = None) -> EncryptedSecret:
    keyset = get_keyset(KEYSET)
    version = version or keyset.active_version
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(keyset.get(version)).encrypt(nonce, secret.encode("ascii"), aad_for(user_id))
    return EncryptedSecret(ciphertext=ciphertext, nonce=nonce, key_version=version)


def decrypt_totp_secret(user_id, nonce: bytes, ciphertext: bytes, key_version: str) -> str:
    try:
        key = get_keyset(KEYSET).get(key_version)
        plaintext = AESGCM(key).decrypt(bytes(nonce), bytes(ciphertext), aad_for(user_id))
    except (InvalidTag, KeyError, ValueError) as exc:
        raise DecryptionError("No se pudo descifrar el secreto TOTP.") from exc
    return plaintext.decode("ascii")
