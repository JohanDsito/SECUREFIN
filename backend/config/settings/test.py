"""Configuración de pruebas.

Genera claves efímeras aleatorias (una por propósito, todas distintas) en un directorio temporal
antes de cargar la configuración base. Nunca se usan secretos reales ni versionados.
"""

from __future__ import annotations

import atexit
import base64
import os
import secrets
import shutil
import tempfile
from pathlib import Path

if not os.environ.get("SECUREFIN_SECRETS_DIR"):
    _secrets = Path(tempfile.mkdtemp(prefix="securefin-test-secrets-"))
    # Las claves efímeras se borran al terminar el proceso: las pruebas no dejan secretos en disco.
    atexit.register(shutil.rmtree, _secrets, True)
    for _name in (
        "django_secret_key",
        "session_hmac_key_v1",
        "token_hmac_key_v1",
        "throttle_hmac_key_v1",
        "totp_key_v1",
    ):
        (_secrets / _name).write_text(base64.b64encode(secrets.token_bytes(32)).decode(), encoding="utf-8")
    os.environ["SECUREFIN_SECRETS_DIR"] = str(_secrets)
os.environ.setdefault("SECUREFIN_PROCESS_ROLE", "test")

from .base import *  # noqa: E402,F401,F403
from .base import DATABASES, env  # noqa: E402

ALLOWED_HOSTS = ["securefin.local", "testserver"]

DATABASES["default"].update(
    {
        "NAME": env("TEST_DB_NAME", "securefin"),
        "USER": env("TEST_DB_USER", "postgres"),
        "PASSWORD": env("TEST_DB_PASSWORD", "postgres"),
        "HOST": env("TEST_DB_HOST", "127.0.0.1"),
        "PORT": env("TEST_DB_PORT", "55432"),
        "CONN_MAX_AGE": 0,
        "TEST": {"NAME": "test_securefin"},
    }
)

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
