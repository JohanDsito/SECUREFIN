"""Carga y validación de claves criptográficas (R8; constitución, Principio III).

Cada propósito criptográfico tiene su propia clave, versionada y distinta de todas las demás:

    SESSION_HMAC_KEYS     verificadores de identificadores de sesión (R2)
    TOKEN_HMAC_KEYS       verificadores de tokens de un solo uso (R7)
    THROTTLE_HMAC_KEYS    resúmenes seudonimizados de la limitación por cuenta (R12)
    TOTP_ENCRYPTION_KEYS  AES-256-GCM de los secretos TOTP (R5)

Las claves se leen de archivos de secreto (por defecto ``/run/secrets``), nunca de la base de
datos. Cada archivo contiene la clave codificada en base64. Las versiones aceptadas de cada
conjunto se declaran con la variable ``<CONJUNTO>_VERSIONS`` (p. ej. ``SESSION_HMAC_KEY_VERSIONS=v2,v1``);
la primera versión es la activa.

Si falta una clave, mide menos de 32 bytes o coincide con otra, la aplicación no arranca
(falla de forma cerrada). Los mensajes de error nunca incluyen valores de claves.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

MIN_KEY_BYTES = 32
VERSION_RE = re.compile(r"^v\d{1,5}$")

# nombre del conjunto -> (prefijo del archivo, variable de versiones)
KEYSETS: dict[str, tuple[str, str]] = {
    "SESSION_HMAC_KEYS": ("session_hmac_key", "SESSION_HMAC_KEY_VERSIONS"),
    "TOKEN_HMAC_KEYS": ("token_hmac_key", "TOKEN_HMAC_KEY_VERSIONS"),
    "THROTTLE_HMAC_KEYS": ("throttle_hmac_key", "THROTTLE_HMAC_KEY_VERSIONS"),
    "TOTP_ENCRYPTION_KEYS": ("totp_key", "TOTP_KEY_VERSIONS"),
}
EXACT_LENGTH = {"TOTP_ENCRYPTION_KEYS": 32}  # AES-256 exige exactamente 32 bytes

PROCESS_ROLES = {"runtime", "migrate", "test"}
OWNER_DB_ROLE = "securefin_owner"


@dataclass(frozen=True)
class KeySet:
    """Conjunto versionado de claves para un único propósito."""

    name: str
    active_version: str
    keys: dict[str, bytes] = field(repr=False)

    @property
    def active(self) -> bytes:
        return self.keys[self.active_version]

    @property
    def accepted_versions(self) -> list[str]:
        """Versión activa primero, después las anteriores aún aceptadas."""
        return list(self.keys.keys())

    def get(self, version: str) -> bytes:
        try:
            return self.keys[version]
        except KeyError as exc:
            raise KeyError(f"{self.name}: versión de clave no aceptada") from exc


def secrets_dir() -> Path:
    return Path(os.environ.get("SECUREFIN_SECRETS_DIR", "/run/secrets"))


def _read_secret_file(filename: str) -> str:
    path = secrets_dir() / filename
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ImproperlyConfigured(f"Falta el secreto obligatorio '{filename}'.") from exc
    if not value:
        raise ImproperlyConfigured(f"El secreto '{filename}' está vacío.")
    return value


def _decode_key(name: str, filename: str, raw: str) -> bytes:
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ImproperlyConfigured(f"{name}: el secreto '{filename}' no es base64 válido.") from exc
    if len(decoded) < MIN_KEY_BYTES:
        raise ImproperlyConfigured(
            f"{name}: el secreto '{filename}' mide menos de {MIN_KEY_BYTES} bytes."
        )
    exact = EXACT_LENGTH.get(name)
    if exact is not None and len(decoded) != exact:
        raise ImproperlyConfigured(f"{name}: el secreto '{filename}' debe medir {exact} bytes.")
    return decoded


def _versions_for(name: str) -> list[str]:
    _prefix, env_var = KEYSETS[name]
    versions = [v.strip() for v in os.environ.get(env_var, "v1").split(",") if v.strip()]
    if not versions:
        raise ImproperlyConfigured(f"{name}: no hay ninguna versión de clave configurada.")
    if len(set(versions)) != len(versions):
        raise ImproperlyConfigured(f"{name}: versiones de clave repetidas.")
    for version in versions:
        if not VERSION_RE.match(version):
            raise ImproperlyConfigured(f"{name}: etiqueta de versión inválida (formato vN).")
    return versions


@lru_cache(maxsize=None)
def get_keyset(name: str) -> KeySet:
    if name not in KEYSETS:
        raise KeyError(f"Conjunto de claves desconocido: {name}")
    prefix, _env = KEYSETS[name]
    keys: dict[str, bytes] = {}
    for version in _versions_for(name):
        filename = f"{prefix}_{version}"
        keys[version] = _decode_key(name, filename, _read_secret_file(filename))
    return KeySet(name=name, active_version=next(iter(keys)), keys=keys)


@lru_cache(maxsize=None)
def django_secret_key() -> str:
    value = _read_secret_file("django_secret_key")
    if len(value.encode("utf-8")) < MIN_KEY_BYTES:
        raise ImproperlyConfigured(
            f"DJANGO_SECRET_KEY: el secreto mide menos de {MIN_KEY_BYTES} bytes."
        )
    return value


def validate_all(db_user: str | None = None) -> None:
    """Valida todas las claves al arrancar (T027). Falla de forma cerrada."""
    seen: dict[bytes, str] = {}
    secret = django_secret_key().encode("utf-8")
    seen[secret] = "DJANGO_SECRET_KEY"
    for name in KEYSETS:
        keyset = get_keyset(name)
        for version, key in keyset.keys.items():
            label = f"{name}[{version}]"
            if key in seen:
                raise ImproperlyConfigured(
                    f"Claves repetidas: {label} coincide con {seen[key]}. "
                    "Cada propósito criptográfico necesita su propia clave."
                )
            seen[key] = label
    validate_process_role(db_user)


def validate_process_role(db_user: str | None) -> None:
    """Un proceso de ejecución nunca puede conectarse como propietario del esquema (U1)."""
    role = os.environ.get("SECUREFIN_PROCESS_ROLE", "runtime")
    if role not in PROCESS_ROLES:
        raise ImproperlyConfigured("SECUREFIN_PROCESS_ROLE debe ser runtime, migrate o test.")
    if role == "runtime" and db_user == OWNER_DB_ROLE:
        raise ImproperlyConfigured(
            "Un proceso de ejecución no puede conectarse como securefin_owner; "
            "usa las credenciales de securefin_app."
        )


def reset_cache() -> None:
    """Solo para pruebas: olvida las claves cargadas."""
    get_keyset.cache_clear()
    django_secret_key.cache_clear()
